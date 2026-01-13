variable "topic_name" {}
variable "subscriptions" {
    type = list(object({
        protocol = string
        endpoint = string
    }))
}
