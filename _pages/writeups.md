---
layout: archive
title: "Write-ups"
permalink: /writeups/
author_profile: true
---

{% assign posts = site.posts | where: "categories", "writeups" %}

<div class="archive">
  {% for post in posts %}
    {% include archive-single.html %}
  {% endfor %}
</div>
