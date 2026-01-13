# SNS Topic for notifying users about the state changes in MediaConvert Job
resource "aws_sns_topic" "topic" {
  name = var.topic_name
  tags = {
    Name = var.topic_name
  }
}

# SNS Subscription
resource "aws_sns_topic_subscription" "subscription" {
  count     = length(var.subscriptions)
  topic_arn = aws_sns_topic.topic.arn
  protocol  = var.subscriptions[count.index].protocol
  endpoint  = var.subscriptions[count.index].endpoint
}
