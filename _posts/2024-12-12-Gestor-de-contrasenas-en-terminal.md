# Tutorial: Gestor de Contraseñas en Terminal con `pass`

`pass` es un gestor de contraseñas ligero, seguro y fácil de usar desde la terminal. Este tutorial te guiará en su instalación, configuración y uso.

---

## **¿Qué es `pass`?**

`pass` utiliza **GPG** para cifrar tus contraseñas y las almacena en un sistema de archivos como archivos simples. Es ideal para usuarios que prefieren una solución minimalista y segura.

---

## **Instalación de `pass`**

### **Paso 1: Instalar `pass`**
En Debian y derivados (Ubuntu, Linux Mint), ejecuta:

```bash
sudo apt update
sudo apt install pass
```

### **Paso 2: Instalar GPG (si no lo tienes)**
`pass` depende de GPG para cifrar las contraseñas. Asegúrate de tenerlo instalado:

```bash
sudo apt install gnupg
```

---

## **Configuración Inicial**

### **Generar una clave GPG**
Si no tienes una clave GPG, genera una:

1. Ejecuta el siguiente comando:
   ```bash
   gpg --full-generate-key
   ```
2. Selecciona los valores predeterminados:
   - Tipo de clave: **RSA y RSA**.
   - Tamaño: **3072 o 4096**.
   - Fecha de expiración: Configúrala según prefieras o déjala sin caducidad.
3. Proporciona tu nombre, correo electrónico y una contraseña segura para proteger la clave.

   Una vez creada, anota el ID de tu clave (algo como `1234ABCD5678EFGH`). Puedes encontrarlo ejecutando:

   ```bash
   gpg --list-keys
   ```

### **Inicializar `pass` con tu clave GPG**

1. Ejecuta:
   ```bash
   pass init <ID_de_tu_clave_GPG>
   ```
   Sustituye `<ID_de_tu_clave_GPG>` por el ID obtenido anteriormente.

---

## **Uso de `pass`**

### **1. Agregar una contraseña**
Para agregar una nueva contraseña:

```bash
pass insert personal/email
```

Escribe la contraseña cuando se te solicite. El archivo cifrado se guardará en la ruta `~/.password-store/personal/email.gpg`.

### **2. Mostrar una contraseña**
Para ver una contraseña guardada:

```bash
pass personal/email
```

### **3. Copiar una contraseña al portapapeles**
Para copiar una contraseña al portapapeles (se eliminará automáticamente tras unos segundos):

```bash
pass -c personal/email
```

### **4. Editar una contraseña**
Si deseas modificar una contraseña existente:

```bash
pass edit personal/email
```

### **5. Eliminar una contraseña**
Para eliminar una contraseña guardada:

```bash
pass rm personal/email
```

---

## **Sincronización con Git (Opcional)**

`pass` puede integrarse con Git para sincronizar tus contraseñas entre dispositivos de forma segura.

### **Configurar Git en `pass`**
1. Inicializa un repositorio Git en el directorio de contraseñas:
   
   ```bash
   pass git init
   ```
2. Agrega un repositorio remoto (asegúrate de que sea privado):
   
   ```bash
   pass git remote add origin <URL_de_tu_repositorio>
   ```
3. Haz tu primer commit:
   
   ```bash
   pass git add .
   pass git commit -m "Primer commit"
   pass git push origin main
   ```

### **Sincronizar cambios**
Para sincronizar tus contraseñas:

```bash
pass git pull
pass git push
```

---

## **Organización de Contraseñas**
Puedes organizar tus contraseñas en carpetas, como en el siguiente ejemplo:

```bash
pass insert work/github
pass insert personal/email
pass insert bank/account
```

Esto crea una estructura jerárquica para facilitar el acceso y la gestión.

---

## **Configuración de Git desde cero**

Para gestionar las contraseñas con `pass` y sincronizarlas en Git, primero configura Git desde cero en tu sistema:

### **1. Configurar Git**

1. Instala Git si no lo tienes:
   ```bash
   sudo apt install git
   ```
2. Configura tu nombre de usuario y correo electrónico globalmente:
   ```bash
   git config --global user.name "Tu Nombre"
   git config --global user.email "tuemail@ejemplo.com"
   ```
3. Verifica la configuración:
   ```bash
   git config --list
   ```

### **2. Crear y subir tus contraseñas a un repositorio privado en GitHub**

1. Ve a [GitHub](https://github.com) y crea un repositorio nuevo (asegúrate de configurarlo como privado).
2. En la terminal, inicializa el repositorio local en el directorio de `pass`:
   ```bash
   cd ~/.password-store
   git init
   git remote add origin https://github.com/tuusuario/tu-repo.git
   ```
3. Agrega los archivos al repositorio y haz un commit inicial:
   ```bash
   git add .
   git commit -m "Primer commit"
   git branch -M main
   git push -u origin main
   ```
4. Asegúrate de usar una clave SSH o token personal para autenticación en GitHub si es necesario.

---

## **Comandos útiles**

### Comandos útiles

- **`pass insert <ruta>`**: Agregar una nueva contraseña.
- **`pass <ruta>`**: Mostrar una contraseña.
- **`pass -c <ruta>`**: Copiar una contraseña al portapapeles.
- **`pass edit <ruta>`**: Editar una contraseña existente.
- **`pass rm <ruta>`**: Eliminar una contraseña.
- **`pass git <comando>`**: Gestionar el repositorio Git de contraseñas.
---

¡Y listo! Ahora puedes gestionar tus contraseñas de forma segura y eficiente directamente desde tu terminal con `pass`.
