---
layout: archive
title: "Tutoriales"
permalink: /tutoriales/
author_profile: true
---

{% include group-by-array collection=site.posts array_name="categories" %}

{% for category in group_names %}
  {% assign posts = group_items[forloop.index0] %}
  <h2 id="{{ category | slugify }}" class="archive__subtitle">{{ category }}</h2>
  {% include posts-category.html taxonomy=category type="grid" %}
{% endfor %}
