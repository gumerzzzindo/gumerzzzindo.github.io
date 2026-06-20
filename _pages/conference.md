---
layout: archive
title: "Conferencias"
permalink: /conference/
author_profile: true
description: "Notas técnicas de congresos de seguridad: EuskalHack, RootedCON y otros."
---

{% assign posts = site.posts | where_exp: "post", "post.categories contains 'conference'" %}

<div class="archive">
  {% for post in posts %}
    {% include archive-single.html %}
  {% endfor %}
</div>
