# INSTALL-MUTILLIDAE.md

> Copy this entire file exactly as-is into `INSTALL-MUTILLIDAE.md` on your laptop (or directly inside your Kali VM).
> This single file contains **every step** to install, initialize, verify, reset, and troubleshoot **Mutillidae** on a Kali Linux VM. Follow commands exactly. Replace example passwords where noted.
> **IMPORTANT:** Run inside an **isolated VM**. Snapshot before performing attacks.

---

# Mutillidae — Complete single-file install & troubleshooting guide

**One-line summary:** Install LAMP, create DB, clone Mutillidae into `/var/www/html/mutillidae`, run web setup → `http://localhost/mutillidae`.

---

## Preconditions (read once)

- Kali Linux inside a VM (VirtualBox / VMware) with sudo/root access.
- Use NAT to download and **switch to Host-only / Internal** network before exploitation.
- Snapshot the VM **before** you start attacks.
- Example DB password used in this file: `mutillidaepass`. **Change it** if you want.

---

## Full copy→paste commands (run in order inside Kali terminal)

> Paste the whole block at once or run line-by-line. The MariaDB interactive step requires input.

```bash
# ----------------------------
# 0. (Optional) Update OS first
# ----------------------------
sudo apt update && sudo apt -y upgrade

# ----------------------------
# 1. Install Apache, MariaDB, PHP and common PHP extensions
# ----------------------------
sudo apt install -y apache2 mariadb-server php php-cli php-mysql php-mbstring php-xml php-curl php-zip git unzip

# ----------------------------
# 2. Enable and start services
# ----------------------------
sudo systemctl enable --now apache2
sudo systemctl enable --now mariadb

# ----------------------------
# 3. Secure MariaDB (interactive)
#    Follow prompts: set a root password, remove anonymous users, disallow remote root, remove test DB.
# ----------------------------
sudo mysql_secure_installation

# ----------------------------
# 4. Create Mutillidae DB and user
#    Replace 'mutillidaepass' with your chosen password if desired.
# ----------------------------
sudo mysql -u root -p <<'SQL'
CREATE DATABASE IF NOT EXISTS mutillidae;
CREATE USER IF NOT EXISTS 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidaepass';
GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';
FLUSH PRIVILEGES;
EXIT;
SQL

# ----------------------------
# 5. Clone Mutillidae into webroot and set permissions
# ----------------------------
cd /var/www/html
sudo rm -rf mutillidae
sudo git clone https://github.com/webpwnized/mutillidae.git
sudo chown -R www-data:www-data mutillidae
sudo find mutillidae -type d -exec chmod 755 {} \;
sudo find mutillidae -type f -exec chmod 644 {} \;

# ----------------------------
# 6. Restart Apache
# ----------------------------
sudo systemctl restart apache2

# ----------------------------
# 7. Open the app (manually inside VM browser)
#    In Kali: open Firefox and go to:
#      http://localhost/mutillidae
#    Or from host if allowed: http://<VM-IP>/mutillidae
# ----------------------------
```

---

## Initialize via browser (exact steps)

1. Inside the Kali VM open a browser (Firefox) and go to `http://localhost/mutillidae`.
2. Look for the **setup / install / set-up-database.php** link (some versions show `install.php` or `set-up-database.php`). Click it.
3. If prompted for DB credentials, enter:

   - DB name: `mutillidae`
   - DB user: `mutillidae`
   - DB pass: `mutillidaepass`
   - Host: `localhost`

4. Click **Initialize / Setup**. Wait for success messages and sample data creation.
5. If you see the Mutillidae UI, set **Security Level** to `low` (for easy practice) or change as required.

---

## Quick verification commands (run if something seems wrong)

```bash
# Check that Apache and MariaDB are active
sudo systemctl status apache2 --no-pager
sudo systemctl status mariadb --no-pager

# Confirm Mutillidae files exist
ls -la /var/www/html/mutillidae

# Check file ownership (first few lines)
sudo stat -c "%U:%G %n" /var/www/html/mutillidae | head -n 20

# Check Apache error log for PHP/DB errors
sudo tail -n 200 /var/log/apache2/error.log

# Test DB login with created user
mysql -u mutillidae -p -D mutillidae
# (enter mutillidaepass)
```

---

## Troubleshooting — common problems & fixes

### 1) Blank page or PHP errors on `http://localhost/mutillidae`

- Inspect Apache error log:

  ```bash
  sudo tail -n 200 /var/log/apache2/error.log
  ```

- Likely cause: missing PHP extensions. Install and restart:

  ```bash
  sudo apt install -y php-mysqli php-pdo php-gd php-json
  sudo systemctl restart apache2
  ```

- If you see `Fatal error: Uncaught Error: Class 'mysqli' not found` → install `php-mysql` and restart Apache.

### 2) Database connection errors (e.g., Access denied)

- Ensure MariaDB is running:

  ```bash
  sudo systemctl status mariadb
  ```

- Verify DB user/password and privileges:

  ```bash
  sudo mysql -u root -p -e "SELECT User,Host FROM mysql.user;"
  sudo mysql -u root -p -e "SHOW GRANTS FOR 'mutillidae'@'localhost';"
  ```

- Recreate DB & user (safe reset):

  ```bash
  sudo mysql -u root -p <<'SQL'
  DROP DATABASE IF EXISTS mutillidae;
  CREATE DATABASE mutillidae;
  DROP USER IF EXISTS 'mutillidae'@'localhost';
  CREATE USER 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidaepass';
  GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';
  FLUSH PRIVILEGES;
  EXIT;
  SQL
  ```

### 3) Permission errors (403 or cannot write)

- Fix ownership and permissions:

  ```bash
  sudo chown -R www-data:www-data /var/www/html/mutillidae
  sudo find /var/www/html/mutillidae -type d -exec chmod 755 {} \;
  sudo find /var/www/html/mutillidae -type f -exec chmod 644 {} \;
  sudo systemctl restart apache2
  ```

### 4) Setup script missing (no install link)

- Search for setup-related files:

  ```bash
  ls /var/www/html/mutillidae | grep -i -E 'setup|install|set-up|init|database'
  ```

- If nothing relevant, re-clone to ensure latest repo:

  ```bash
  cd /var/www/html
  sudo rm -rf mutillidae
  sudo git clone https://github.com/webpwnized/mutillidae.git
  sudo chown -R www-data:www-data mutillidae
  sudo systemctl restart apache2
  ```

- Revisit `http://localhost/mutillidae`.

### 5) PHP version incompatibility

- Kali may ship newer PHP. Ensure required extensions exist (`php-mysql`, `php-mbstring`, `php-xml`, `php-curl`). If the app expects an older PHP behavior and fails, use the Docker container option (see Docker section below).

### 6) `500 Internal Server Error`

- Most often due to PHP fatal error or permission. Check `/var/log/apache2/error.log` and fix per message.

---

## Reset / Clean reinstall (useful during exams)

```bash
# remove files
sudo rm -rf /var/www/html/mutillidae

# drop and recreate DB
sudo mysql -u root -p -e "DROP DATABASE IF EXISTS mutillidae; CREATE DATABASE mutillidae;"

# re-clone
cd /var/www/html
sudo git clone https://github.com/webpwnized/mutillidae.git
sudo chown -R www-data:www-data mutillidae
sudo systemctl restart apache2
```

Then open `http://localhost/mutillidae` and run the setup/initialize.

---

## Docker alternative (fast & isolated)

If you prefer a container (skips LAMP install):

```bash
sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo docker pull webpwnized/mutillidae
sudo docker run --rm -d -p 1337:80 --name mutillidae webpwnized/mutillidae
# open: http://localhost:1337
# stop with:
sudo docker stop mutillidae
```

Docker is recommended for reproducible quick installs. If the exam environment restricts Docker, use the LAMP method above.

---

## Safety & networking (MANDATORY)

- **Do not** expose the VM to the Internet while performing attacks. NAT is OK for downloads; **switch to Host-only/Internal** for attacking.
- Disable shared clipboard/folders to avoid host contamination.
- Snapshot BEFORE each set of experiments, revert after finishing.
- Remove VirtualBox/VMware port-forward rules exposing port 80 or 1337.
- Optional firewall to block outbound HTTP while testing (adjust host-only subnet as needed):

  ```bash
  sudo apt install -y ufw
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  # allow http from host-only subnet (example 192.168.56.0/24)
  sudo ufw allow from 192.168.56.0/24 to any port 80 proto tcp
  sudo ufw enable
  ```

---

## Useful hints & exam shortcuts

- Use `http://localhost/mutillidae` inside the VM — no external network required.
- Change Security Level dropdown (in-app) to `low` for easy practice.
- Mutillidae menu includes lessons/hints — use them if allowed.
- Common vulnerable targets: login/search forms (SQLi), message boards/comments (XSS), file-include pages (`?page=`), file upload pages, command injection forms.

---

## Commands for quick status & logs (paste when troubleshooting)

```bash
# Check listening ports (exposure)
sudo ss -ltnp

# Apache error log
sudo tail -n 300 /var/log/apache2/error.log

# Apache access log
sudo tail -n 200 /var/log/apache2/access.log

# MariaDB log
sudo journalctl -u mariadb --no-pager -n 200

# PHP version & loaded modules
php -v
php -m

# Find possible setup/install files
ls -la /var/www/html/mutillidae | grep -i -E 'install|setup|initialize|db|create'
```

---

## Fastest recovery if you run out of time during exam

1. Revert to clean snapshot and start over (fastest & safest).
2. If snapshot unavailable: use **Reset / Clean reinstall** steps above.
3. For networking problems, open `http://localhost/mutillidae` inside the VM browser — bypasses host network issues.

---

## Final one-line checklist to paste into your notes

- Snapshot VM BEFORE attacks — YES / NO
- LAMP installed & services running — YES / NO (`sudo systemctl status apache2 mariadb`)
- Mutillidae files present `/var/www/html/mutillidae` — YES / NO
- Setup page run & DB initialized — YES / NO
- Mutillidae accessible at `http://localhost/mutillidae` — YES / NO
- VM network switched to Host-only/internal for attacks — YES / NO

---

## Last-minute reminder

This single `.md` file contains everything you need. Copy it into `INSTALL-MUTILLIDAE.md`, push it to your private GitHub repo, and `git clone` it inside your Kali VM during the exam. Test the flow once now if possible so you’re familiar with the sequence.

Good luck — you’ve got this. 🚀
