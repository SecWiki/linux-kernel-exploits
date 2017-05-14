# caps_to_root

caps_to_root

Vulnerability reference:
 * [N/A](https://www.exploit-db.com/exploits/15916/)  

## Kernels
```
2.6.34, 2.6.35, 2.6.36
```   

## Usage
```
gcc -w caps-to-root.c -o caps-to-root
sudo setcap cap_sys_admin+ep caps-to-root
./caps-to-root
```  

![root](root.png)





