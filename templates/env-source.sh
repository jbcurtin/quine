#!/usr/bin/env bash

{% for key, value in ENVVars.items() %}
export {{key}}="{{value}}"
{% endfor %}
