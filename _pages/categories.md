---
layout: categories
title: "Categorías"
permalink: /categories/
author_profile: true
---

<div class="categories-archive">
  {% assign categories_list = site.categories %}
  
  {% if categories_list.first[0] == null %}
    <p>No hay categorías.</p>
  {% else %}
    {% for category in categories_list %}
      {% assign category_posts = category[1] | size %}
      <div class="category-item">
        <h3>
          <a href="/categories/#{{ category[0] | slugify }}">{{ category[0] }}</a>
          <span class="post-count">({{ category_posts }})</span>
        </h3>
        <ul>
          {% for post in category[1] limit:5 %}
            <li><a href="{{ post.url }}">{{ post.title }}</a></li>
          {% endfor %}
          {% if category_posts > 5 %}
            <li><a href="/categories/#{{ category[0] | slugify }}">Ver todas...</a></li>
          {% endif %}
        </ul>
      </div>
    {% endfor %}
  {% endif %}
</div>
