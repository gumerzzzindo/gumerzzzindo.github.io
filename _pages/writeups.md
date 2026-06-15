---
layout: archive
title: "Write-ups"
permalink: /writeups/
author_profile: true
description: "Writeups de máquinas HackTheBox y DockerLabs: explotación, escalada de privilegios, CVEs y post-explotación. Soluciones detalladas con metodología reproducible."
---

{% assign posts = site.posts | where_exp: "post", "post.categories contains 'writeups' or post.categories contains 'htb' or post.categories contains 'dockerlabs'" %}

<div class="archive">
  {% for post in posts %}
    {% include archive-single.html %}
  {% endfor %}
</div>
