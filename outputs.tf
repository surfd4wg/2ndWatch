output "IPAddress-InstanceName" {
  value = [aws_eip.webserver.*.public_ip, "-", aws_instance.winrm.*.tags.Name]
}

output "Admin_Username" {
  value = "Administrator"
}

output "Admin_Password" {
  value = aws_instance.winrm.*.password_data
}

output "admin_passwords_decrypted" {
  value = [
    for inst in aws_instance.winrm : rsadecrypt(inst.password_data, file(var.private_key_path))
  ]
}
