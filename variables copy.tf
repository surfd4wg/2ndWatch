variable "access_key" {
  description = "Access Key to AWS account"
  default     = "XXXXXXXXXXXXXXXXXXXX"
}

variable "secret_key" {
  description = "Secret Key to AWS account"
  default     = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}

variable "ARMKEY" {
  description = "Armor License Key"
  default = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
}

variable "public_key_path" {
  description = "Path to the public SSH key you want to bake into the instance."
  default     = "~/.ssh/<keypairname>.pub"
}

variable "private_key_path" {
  description = "Path to the private SSH key, used to access the instance."
  default     = "~/.ssh/<keypairname>.pem"
}

variable "admin_password" {
  description = "Windows Administrator password to login as for provisioning"
  default = "<admin password>"
}

variable "key_name" {
  description = "Name of the SSH keypair to use in AWS."
  default = "<keypairname>"
}

variable "aws_region" {
  description = "AWS region to launch servers."
  default     = "us-east-1"
}

variable "aws_availzone" {
  description = "AWS availibility zone to launch in."
  default     = "us-east-1a"
}

variable "instance_name" {
  description = "Name of your instance"
  default     = "SSM-Windows"
}

variable "INSTANCE_USERNAME" {
  description = "user"
  default = "<non-admin username>"
}

variable "INSTANCE_PASSWORD" {
  description = "pass"
  default = "P<non-admin password>"
}

variable "instance_count" {
  description = "number of instances to spin up"
  default = 100
}

variable "pbase" {
  type = string
  default = ""
}

variable "ptext" {
  type = string
  default = ""
}

variable "ssm_managed" {
  description = "Set to YES to be managed by AWS Systems Manager - SSM - via tagging"
  default = "YES"
}

