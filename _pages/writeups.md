---
layout: archive
title: "Write-ups"
permalink: /writeups/
author_profile: true
description: "Writeups de máquinas HackTheBox y DockerLabs: explotación, escalada de privilegios, CVEs y post-explotación. Soluciones detalladas con metodología reproducible."
---

<div class="archive">
  {% for post in site.posts %}
    {% if post.categories contains 'writeups' or post.categories contains 'htb' or post.categories contains 'dockerlabs' %}
      {% include archive-single.html %}
    {% endif %}
  {% endfor %}
</div>
