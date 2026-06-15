---
layout: archive
title: "Write-ups"
permalink: /writeups/
author_profile: true
---

{% assign posts = site.posts | where_exp: "post", "post.categories contains 'writeups' or post.categories contains 'htb' or post.categories contains 'dockerlabs'" %}

<div class="archive">
  {% for post in posts %}
    {% include archive-single.html %}
  {% endfor %}
</div>
