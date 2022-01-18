resource "aws_resourcegroups_group" "SSMManaged_WIN2016" {
  name = "SSMManaged_WIN2016"

  resource_query {
    query = <<JSON
{
  "ResourceTypeFilters": [
    "AWS::EC2::Instance"
  ],
  "TagFilters": [
    {
      "Key": "SSM",
      "Values": ["YES"]
    }
  ]
}
JSON
  }
}
