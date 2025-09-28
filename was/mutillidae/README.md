# Mutillidae — One-Page Install & Run (Kali VM)

**Quick note:** Run inside an isolated Kali VM (host-only/internal network). Snapshot the VM BEFORE performing attacks.

---

## Preconditions

- Kali Linux (VM).
- sudo / root access.
- VM network: NAT ok for downloads → switch to Host-only/internal before attacks.

---

## Install (copy→paste)

```bash
# update
sudo apt update && sudo apt -y upgrade

# install LAMP essentials
sudo apt install -y apache2 mariadb-server php php-cli php-mysql php-mbstring php-xml php-curl php-zip git unzip

# enable services
sudo systemctl enable --now apache2
sudo systemctl enable --now mariadb

# secure MariaDB (interactive)
sudo mysql_secure_installation

# create DB + user (replace password if desired)
sudo mysql -u root -p <<'SQL'
CREATE DATABASE mutillidae;
CREATE USER 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidaepass';
GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';
FLUSH PRIVILEGES;
EXIT;
SQL

# clone Mutillidae and set permissions
cd /var/www/html
sudo rm -rf mutillidae
sudo git clone https://github.com/webpwnized/mutillidae.git
sudo chown -R www-data:www-data mutillidae
sudo find mutillidae -type d -exec chmod 755 {} \;
sudo find mutillidae -type f -exec chmod 644 {} \;

# restart
sudo systemctl restart apache2
```
