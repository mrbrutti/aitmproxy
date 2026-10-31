#!/bin/zsh
# Continuous benign sample traffic through the aitmproxy demo proxy, so the
# inspector's flow list streams live. All requests hit the local sample site.
P=http://127.0.0.1:8080
T=http://127.0.0.1:9000
paths=( "/" "/products.html" "/about.html" "/assets/app.css" "/assets/app.js" "/api/products.json" "/api/users.json" "/api/products.json?page=2" "/products.html?q=widget" "/api/users.json?role=member" "/api/products.json?sort=price" )
N=${1:-170}
for i in $(seq 1 $N); do
  p=${paths[$((RANDOM % ${#paths[@]} + 1))]}
  if (( i % 9 == 0 )); then
    curl -s -x $P -X POST -H "Content-Type: application/json" --data '{"cart":[1,2],"qty":2}' "$T/api/orders" -o /dev/null
  else
    curl -s -x $P "$T$p" -o /dev/null
  fi
  sleep 0.12
done
