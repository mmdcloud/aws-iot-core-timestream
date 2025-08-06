
variable "bucket_name" {}
variable "force_destroy" {}
variable "versioning_enabled" {}
variable "objects" {
  type = list(object({
    source = string
    key    = string
  }))
  default = []
}
