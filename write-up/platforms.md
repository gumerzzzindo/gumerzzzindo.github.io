---
layout: page
title: "Write-ups por Plataforma"
permalink: /platforms/
---

# Write-ups por Plataforma

Aquí puedes ver mis write-ups agrupados por plataforma.

- **Hack The Box**:  
  {% assign htb_posts = site.categories.htb %}
  {% for post in htb_posts %}
    - [{{ post.title }}]({{ post.url }})
  {% endfor %}

- **CTF**:  
  {% assign ctf_posts = site.categories.ctf %}
  {% for post in ctf_posts %}
    - [{{ post.title }}]({{ post.url }})
  {% endfor %}

- **Docker Labs**:  
  {% assign rootedcon_posts = site.categories.rootedcon %}
  {% for post in rootedcon_posts %}
    - [{{ maquina_domain_dockerlabs.md }}]({{ write-up\maquina_domain_dockerlabs.md }})
  {% endfor %}
