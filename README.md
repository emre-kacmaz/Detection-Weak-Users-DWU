# Detection-Weak-Users-DWU
This program is developed to detect weak active directory user's passwords.

We know that the weakest link is people.

The majority of data breaches are of human origin.

So we decided to develop a software that detects weak accounts in active directory.

Usage;

Firstly you should type target group to detect weak accounts.If you want to scan all active directory environment then you can type 1.

Then you should enter your domain FQDN?(example: mydomain.local)

After you enter all necessary info,the program will start to scan your target group.

The program send DC sync to Domain Controller and requests selected accounts password NTLM Hash.

Then it takes first member of your wordlist and calculate it's NTLM hash.

If Account's NTLM hash equals to wordlist members hash,It writes the screen "Breached Password Deteced and Username"

By means of the program you can detect your weak ad accounts.And you can see  accounts which are breakable in brute force attacks.Because adversaries generally use this type of most used password lists.

Hope it is useful for you.

Caution : This program uses mimikatz for DCSync, so be careful :)

![ekage](https://user-images.githubusercontent.com/14946224/198968496-0a4ddc6d-2e88-4634-9f11-e7559a411733.png)
