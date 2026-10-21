terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "~> 1.27.0"
    }
  }
}

variable "postgres_admin_user" {
  type = string
}

variable "postgres_admin_password" {
  type      = string
  sensitive = true
}

variable "postgres_db" {
  description = "Existing maintenance database used to administer PostgreSQL."
  type        = string
  default     = "postgres"
}

variable "postgres_identity_db" {
  description = "Separate identity application database created by Terraform."
  type        = string
  default     = "identity"

  validation {
    condition = (
      length(trimspace(var.postgres_identity_db)) > 0 &&
      var.postgres_identity_db != var.postgres_db &&
      !contains(["postgres", "template0", "template1"], var.postgres_identity_db)
    )
    error_message = "The identity database must have its own name, separate from the maintenance and template databases."
  }
}

variable "postgres_bff_db" {
  description = "Separate BFF application database created by Terraform."
  type        = string
  default     = "bff"

  validation {
    condition = (
      length(trimspace(var.postgres_bff_db)) > 0 &&
      var.postgres_bff_db != var.postgres_db &&
      var.postgres_bff_db != var.postgres_identity_db &&
      !contains(["postgres", "template0", "template1"], var.postgres_bff_db)
    )
    error_message = "The BFF database must be separate from identity, maintenance, and template databases."
  }
}

variable "postgres_host" {
  type    = string
  default = "localhost"
}

variable "postgres_port" {
  type    = number
  default = 5432
}

variable "postgres_identity_app_password" {
  type      = string
  sensitive = true
  ephemeral = true

  validation {
    condition     = length(var.postgres_identity_app_password) >= 32
    error_message = "Use an application password of at least 32 characters."
  }
}

variable "postgres_identity_migrator_password" {
  type      = string
  sensitive = true
  ephemeral = true

  validation {
    condition     = length(var.postgres_identity_migrator_password) >= 32
    error_message = "Use a migration password of at least 32 characters."
  }
}

# Increment the corresponding version whenever its write-only password changes.
variable "postgres_identity_app_password_version" {
  type    = string
  default = "1"
}

variable "postgres_identity_migrator_password_version" {
  type    = string
  default = "1"
}

variable "postgres_bff_app_password" {
  type      = string
  sensitive = true
  ephemeral = true

  validation {
    condition     = length(var.postgres_bff_app_password) >= 32
    error_message = "Use a BFF application password of at least 32 characters."
  }
}

variable "postgres_bff_migrator_password" {
  type      = string
  sensitive = true
  ephemeral = true

  validation {
    condition     = length(var.postgres_bff_migrator_password) >= 32
    error_message = "Use a BFF migration password of at least 32 characters."
  }
}

variable "postgres_bff_app_password_version" {
  type    = string
  default = "1"
}

variable "postgres_bff_migrator_password_version" {
  type    = string
  default = "1"
}

provider "postgresql" {
  host     = var.postgres_host
  port     = var.postgres_port
  database = var.postgres_db
  username = var.postgres_admin_user
  password = var.postgres_admin_password
  # Matches the current local Docker PostgreSQL deployment.
  sslmode = "disable"
}

locals {
  # Some existing identity models use the default public schema.
  identity_schemas = toset(["identity", "key_manager", "public"])
  identity_app_privileges = {
    table    = ["SELECT", "INSERT", "UPDATE", "DELETE"]
    sequence = ["USAGE", "SELECT"]
    routine  = ["EXECUTE"]
  }
  identity_objects = {
    for pair in setproduct(local.identity_schemas, keys(local.identity_app_privileges)) :
    "${pair[0]}.${pair[1]}" => { schema = pair[0], object_type = pair[1] }
  }
  # public holds Alembic's version table; only bff is exposed to the app.
  bff_schemas = toset(["bff", "public"])
  bff_app_privileges = {
    table    = ["SELECT", "INSERT", "UPDATE", "DELETE"]
    sequence = ["USAGE", "SELECT"]
    routine  = ["EXECUTE"]
  }
  bff_objects = {
    for pair in setproduct(local.bff_schemas, keys(local.bff_app_privileges)) :
    "${pair[0]}.${pair[1]}" => { schema = pair[0], object_type = pair[1] }
  }
  bff_app_objects = {
    for name, object in local.bff_objects : name => object if object.schema == "bff"
  }
}

# This role owns schemas and objects, but cannot log in directly.
resource "postgresql_role" "identity_owner" {
  name                      = "identity_owner"
  login                     = false
  inherit                   = false
  superuser                 = false
  create_database           = false
  create_role               = false
  replication               = false
  bypass_row_level_security = false
  roles                     = []
}

resource "postgresql_database" "identity" {
  name     = var.postgres_identity_db
  owner    = postgresql_role.identity_owner.name
  template = "template0"
  encoding = "UTF8"
}

resource "postgresql_role" "identity_app" {
  name                      = "identity_app"
  login                     = true
  inherit                   = false
  superuser                 = false
  create_database           = false
  create_role               = false
  replication               = false
  bypass_row_level_security = false
  roles                     = []
  search_path               = ["public"]
  password_wo               = var.postgres_identity_app_password
  password_wo_version       = var.postgres_identity_app_password_version
}

# Alembic must SET LOCAL ROLE identity_owner inside each migration transaction.
# This gives new objects the owner role and applies its default app grants.
# NOINHERIT keeps owner privileges inactive until the migration explicitly sets it.
resource "postgresql_role" "identity_migrator" {
  name                      = "identity_migrator"
  login                     = true
  inherit                   = false
  superuser                 = false
  create_database           = false
  create_role               = false
  replication               = false
  bypass_row_level_security = false
  roles                     = [postgresql_role.identity_owner.name]
  search_path               = ["public"]
  password_wo               = var.postgres_identity_migrator_password
  password_wo_version       = var.postgres_identity_migrator_password_version
}

resource "postgresql_schema" "identity" {
  for_each = local.identity_schemas
  database = postgresql_database.identity.name
  name     = each.value
  owner    = postgresql_role.identity_owner.name

  # Changing schema ownership does not transfer pre-existing table ownership.
  # Existing application tables must also be transferred to identity_owner.
  drop_cascade = false
}

# Order PUBLIC -> app -> migrator grants to avoid concurrent ACL catalog updates.
resource "postgresql_grant" "maintenance_public_database" {
  database    = var.postgres_db
  role        = "public"
  object_type = "database"
  privileges  = []
}

resource "postgresql_grant" "identity_public_database" {
  database    = postgresql_database.identity.name
  role        = "public"
  object_type = "database"
  privileges  = []
}

resource "postgresql_grant" "identity_app_database" {
  database    = postgresql_database.identity.name
  role        = postgresql_role.identity_app.name
  object_type = "database"
  privileges  = ["CONNECT"]
  depends_on  = [postgresql_grant.identity_public_database]
}

resource "postgresql_grant" "identity_migrator_database" {
  database    = postgresql_database.identity.name
  role        = postgresql_role.identity_migrator.name
  object_type = "database"
  privileges  = ["CONNECT"]
  depends_on  = [postgresql_grant.identity_app_database]
}

resource "postgresql_grant" "identity_public_schema" {
  for_each    = postgresql_schema.identity
  database    = postgresql_database.identity.name
  schema      = each.value.name
  role        = "public"
  object_type = "schema"
  privileges  = []
}

resource "postgresql_grant" "identity_app_schema" {
  for_each    = postgresql_schema.identity
  database    = postgresql_database.identity.name
  schema      = each.value.name
  role        = postgresql_role.identity_app.name
  object_type = "schema"
  privileges  = ["USAGE"]
  depends_on  = [postgresql_grant.identity_public_schema]
}

resource "postgresql_grant" "identity_migrator_schema" {
  for_each    = postgresql_schema.identity
  database    = postgresql_database.identity.name
  schema      = each.value.name
  role        = postgresql_role.identity_migrator.name
  object_type = "schema"
  privileges  = ["USAGE"]
  depends_on  = [postgresql_grant.identity_app_schema]
}

# Empty objects lists cover all currently existing objects of each kind.
resource "postgresql_grant" "identity_public_objects" {
  for_each    = local.identity_objects
  database    = postgresql_database.identity.name
  schema      = postgresql_schema.identity[each.value.schema].name
  role        = "public"
  object_type = each.value.object_type
  privileges  = []
}

resource "postgresql_grant" "identity_app_objects" {
  for_each    = local.identity_objects
  database    = postgresql_database.identity.name
  schema      = postgresql_schema.identity[each.value.schema].name
  role        = postgresql_role.identity_app.name
  object_type = each.value.object_type
  privileges  = local.identity_app_privileges[each.value.object_type]
  depends_on  = [postgresql_grant.identity_public_objects]
}

resource "postgresql_grant" "identity_migrator_objects" {
  for_each    = local.identity_objects
  database    = postgresql_database.identity.name
  schema      = postgresql_schema.identity[each.value.schema].name
  role        = postgresql_role.identity_migrator.name
  object_type = each.value.object_type
  privileges  = []
  depends_on  = [postgresql_grant.identity_app_objects]
}

# Routine EXECUTE is granted to PUBLIC globally by PostgreSQL's defaults.
# Revoke globally: a per-schema REVOKE cannot override that global default.
resource "postgresql_default_privileges" "identity_public_routines" {
  database    = postgresql_database.identity.name
  owner       = postgresql_role.identity_owner.name
  role        = "public"
  object_type = "routine"
  privileges  = []
}

# These grants apply immediately when identity_owner creates future objects.
resource "postgresql_default_privileges" "identity_app" {
  for_each    = local.identity_objects
  database    = postgresql_database.identity.name
  schema      = postgresql_schema.identity[each.value.schema].name
  owner       = postgresql_role.identity_owner.name
  role        = postgresql_role.identity_app.name
  object_type = each.value.object_type
  privileges  = local.identity_app_privileges[each.value.object_type]
  depends_on  = [postgresql_default_privileges.identity_public_routines]
}

resource "postgresql_role" "bff_owner" {
  name                      = "bff_owner"
  login                     = false
  inherit                   = false
  superuser                 = false
  create_database           = false
  create_role               = false
  replication               = false
  bypass_row_level_security = false
  roles                     = []
}

resource "postgresql_database" "bff" {
  name     = var.postgres_bff_db
  owner    = postgresql_role.bff_owner.name
  template = "template0"
  encoding = "UTF8"
}

resource "postgresql_role" "bff_app" {
  name                      = "bff_app"
  login                     = true
  inherit                   = false
  superuser                 = false
  create_database           = false
  create_role               = false
  replication               = false
  bypass_row_level_security = false
  roles                     = []
  search_path               = ["public"]
  password_wo               = var.postgres_bff_app_password
  password_wo_version       = var.postgres_bff_app_password_version
}

# Alembic uses SET LOCAL ROLE bff_owner; its login has no direct table grants.
resource "postgresql_role" "bff_migrator" {
  name                      = "bff_migrator"
  login                     = true
  inherit                   = false
  superuser                 = false
  create_database           = false
  create_role               = false
  replication               = false
  bypass_row_level_security = false
  roles                     = [postgresql_role.bff_owner.name]
  search_path               = ["public"]
  password_wo               = var.postgres_bff_migrator_password
  password_wo_version       = var.postgres_bff_migrator_password_version
}

resource "postgresql_schema" "bff" {
  for_each     = local.bff_schemas
  database     = postgresql_database.bff.name
  name         = each.value
  owner        = postgresql_role.bff_owner.name
  drop_cascade = false
}

resource "postgresql_grant" "bff_public_database" {
  database    = postgresql_database.bff.name
  role        = "public"
  object_type = "database"
  privileges  = []
}

resource "postgresql_grant" "bff_app_database" {
  database    = postgresql_database.bff.name
  role        = postgresql_role.bff_app.name
  object_type = "database"
  privileges  = ["CONNECT"]
  depends_on  = [postgresql_grant.bff_public_database]
}

resource "postgresql_grant" "bff_migrator_database" {
  database    = postgresql_database.bff.name
  role        = postgresql_role.bff_migrator.name
  object_type = "database"
  privileges  = ["CONNECT"]
  depends_on  = [postgresql_grant.bff_app_database]
}

resource "postgresql_grant" "bff_public_schema" {
  for_each    = postgresql_schema.bff
  database    = postgresql_database.bff.name
  schema      = each.value.name
  role        = "public"
  object_type = "schema"
  privileges  = []
}

resource "postgresql_grant" "bff_app_schema" {
  database    = postgresql_database.bff.name
  schema      = postgresql_schema.bff["bff"].name
  role        = postgresql_role.bff_app.name
  object_type = "schema"
  privileges  = ["USAGE"]
  depends_on  = [postgresql_grant.bff_public_schema]
}

resource "postgresql_grant" "bff_migrator_schema" {
  for_each    = postgresql_schema.bff
  database    = postgresql_database.bff.name
  schema      = each.value.name
  role        = postgresql_role.bff_migrator.name
  object_type = "schema"
  privileges  = ["USAGE"]
  depends_on  = [postgresql_grant.bff_app_schema]
}

resource "postgresql_grant" "bff_public_objects" {
  for_each    = local.bff_objects
  database    = postgresql_database.bff.name
  schema      = postgresql_schema.bff[each.value.schema].name
  role        = "public"
  object_type = each.value.object_type
  privileges  = []
}

resource "postgresql_grant" "bff_app_objects" {
  for_each    = local.bff_app_objects
  database    = postgresql_database.bff.name
  schema      = postgresql_schema.bff[each.value.schema].name
  role        = postgresql_role.bff_app.name
  object_type = each.value.object_type
  privileges  = local.bff_app_privileges[each.value.object_type]
  depends_on  = [postgresql_grant.bff_public_objects]
}

resource "postgresql_grant" "bff_migrator_objects" {
  for_each    = local.bff_objects
  database    = postgresql_database.bff.name
  schema      = postgresql_schema.bff[each.value.schema].name
  role        = postgresql_role.bff_migrator.name
  object_type = each.value.object_type
  privileges  = []
  depends_on  = [postgresql_grant.bff_app_objects]
}

resource "postgresql_default_privileges" "bff_public_routines" {
  database    = postgresql_database.bff.name
  owner       = postgresql_role.bff_owner.name
  role        = "public"
  object_type = "routine"
  privileges  = []
}

resource "postgresql_default_privileges" "bff_app" {
  for_each    = local.bff_app_objects
  database    = postgresql_database.bff.name
  schema      = postgresql_schema.bff[each.value.schema].name
  owner       = postgresql_role.bff_owner.name
  role        = postgresql_role.bff_app.name
  object_type = each.value.object_type
  privileges  = local.bff_app_privileges[each.value.object_type]
  depends_on  = [postgresql_default_privileges.bff_public_routines]
}
