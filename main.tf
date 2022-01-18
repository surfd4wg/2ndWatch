# Specify the provider and access details
provider "aws" {
  region = var.aws_region
  access_key = var.access_key
  secret_key = var.secret_key
}

# Lookup the correct AMI based on the region specified
data "aws_ami" "amazon_windows_2016" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["*Windows_Server-2016-English-Full-Base-2021.04.14*"]
  }

}

resource "aws_instance" "winrm" {
  # The connection block tells our provisioner how to
  # communicate with the resource (instance) using WinRM
    get_password_data = true
    connection {
      host = self.public_ip
      type     = "winrm"
      user     = "Administrator"
     private_key = file(var.private_key_path)
    timeout = "30m"
    }

  # Change instance type for appropriate use case
    instance_type = "t3.medium"
 
  #ami    
  #  ami = "ami-056f139b85f494248"
  # ami = "ami-04c7f5a0e4cc067e0"
  ami = data.aws_ami.amazon_windows_2016.image_id
  # Root storage
  # Terraform doesn't allow encryption of root at this time
  # encrypt volume after deployment.
  root_block_device {
    volume_type = "gp2"
    volume_size = 40
    delete_on_termination = true
  }

  # AZ to launch in
  availability_zone = var.aws_availzone

  # VPC subnet and SGs
  subnet_id = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.allowall.id]
  associate_public_ip_address = "true"
  iam_instance_profile = "${aws_iam_instance_profile.ssm_profile.name}"
  # The number of instances to spin up
  count = var.instance_count
  # The name of our SSH keypair you've created and downloaded
  # from the AWS console.
  #
  # https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#KeyPairs
  #
  key_name = var.key_name
#  admin_password_base = aws_instance.winrm.*.password_data

# Ec2 user data, WinRM and PowerShell Provision Functions
   user_data = <<EOF
	<powershell>
	#Allow All TLS versions 
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3
		[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"
	#Windows Remoting
		net user ${var.INSTANCE_USERNAME} '${var.INSTANCE_PASSWORD}' /add /y
		net localgroup administrators ${var.INSTANCE_USERNAME} /add
		winrm quickconfig -q
		winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="300"}'
		winrm set winrm/config '@{MaxTimeoutms="1800000"}'
		winrm set winrm/config/service '@{AllowUnencrypted="true"}'
		winrm set winrm/config/service/auth '@{Basic="true"}'
		netsh advfirewall firewall add rule name="WinRM 5985" protocol=TCP dir=in localport=5985 action=allow
		netsh advfirewall firewall add rule name="WinRM 5986" protocol=TCP dir=in localport=5986 action=allow
		net stop winrm
		sc.exe config winrm start=auto
		net start winrm

	#Chrome
		$LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)

	#IIS
		Install-WindowsFeature -name Web-Server -IncludeManagementTools
		Invoke-WebRequest https://armorscripts.s3.amazonaws.com/WINscripts/WIN2016.png -outfile c:\inetpub\wwwroot\WIN2016.png
		Invoke-WebRequest https://armorscripts.s3.amazonaws.com/WINscripts/iisstart2016.htm -outfile c:\inetpub\wwwroot\iisstart.htm

	#ssh
		mkdir c:\OpenSSH
		cd c:\OpenSSH
		Invoke-WebRequest https://armorscripts.s3.amazonaws.com/sshinstall.ps1 -outfile sshinstall.ps1 
		.\sshinstall.ps1

	#CPU Stress
		mkdir c:\CPUstress
		cd c:\CPUstress
		Invoke-WebRequest https://armorscripts.s3.amazonaws.com/WINscripts/CPUSTRES64.EXE -outfile CPUstress.exe

	#Armor Agent
		# The armor agent will be installed using the AWS SSMv17.yml script

        #AWS SSM Agent
                Invoke-WebRequest `
                https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe `
                -OutFile $env:USERPROFILE\Desktop\SSMAgent_latest.exe
                Start-Process `
                -FilePath $env:USERPROFILE\Desktop\SSMAgent_latest.exe `
                -ArgumentList "/S"

	</powershell>
	EOF

	tags = {
		#Name = var.instance_name
		Name = "SSMtest-W2016-TF-${count.index + 1}"
		"SSMManaged_WIN2016" = var.ssm_managed

	}

}
