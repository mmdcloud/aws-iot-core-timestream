# Role
resource "aws_iam_role" "role" {
  name               = var.role_name
  description        = var.role_description
  assume_role_policy = var.assume_role_policy
}

# Policy
resource "aws_iam_policy" "policy" {
  name        = var.policy_name
  description = var.policy_description
  policy      = var.policy
}

# Role-Policy Attachment
resource "aws_iam_role_policy_attachment" "role-policy-attachment" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}