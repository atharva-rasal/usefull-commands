
---

## `install_mutillidae_kali.sh` (copy-paste)
```bash
#!/bin/bash
# install_mutillidae_kali.sh
# Run as a user with sudo. Replace DB password if desired.

set -e

echo "Updating system..."
sudo apt update && sudo apt -y upgrade

echo "Installing Apache, MariaDB, PHP and utilities..."
sudo apt install -y apache2 mariadb-server php php-cli php-mysql php-mbstring php-xml php-curl php-zip git unzip

echo "Enabling services..."
sudo systemctl enable --now apache2
sudo systemctl enable --now mariadb

echo "Please run: sudo mysql_secure_installation  (interactive step)"
read -p "Press ENTER after you finish mysql_secure_installation ..." dummy

echo "Creating database and user (mutillidae / mutillidaepass)..."
sudo mysql -u root -p <<'SQL'
CREATE DATABASE IF NOT EXISTS mutillidae;
CREATE USER IF NOT EXISTS 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidaepass';
GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';
FLUSH PRIVILEGES;
EXIT;
SQL

echo "Cloning Mutillidae..."
cd /var/www/html
sudo rm -rf mutillidae
sudo git clone https://github.com/webpwnized/mutillidae.git
sudo chown -R www-data:www-data mutillidae
sudo find mutillidae -type d -exec chmod 755 {} \;
sudo find mutillidae -type f -exec chmod 644 {} \;

echo "Restarting Apache..."
sudo systemctl restart apache2

echo "Done. Open: http://localhost/mutillidae and run the setup/install page."
