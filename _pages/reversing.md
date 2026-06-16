---
layout: archive
title: "Reversing"
permalink: /reversing/
author_profile: true
description: "Ingeniería inversa: assembly x86/x64, análisis estático y dinámico de binarios, crackmes, anti-debugging y herramientas como Ghidra, IDA y x64dbg."
---

{% assign posts = site.posts | where_exp: "post", "post.categories contains 'reversing'" %}

<div class="archive">
  {% for post in posts %}
    {% include archive-single.html %}
  {% endfor %}
</div>
