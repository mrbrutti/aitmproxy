#!/bin/zsh
# Continuous benign sample traffic through the kit proxy, so the inspector's
# flow list streams live while you record. Runs until you press Ctrl-C.
P=http://127.0.0.1:18080
T=http://127.0.0.1:19000
paths=( "/" "/products.html" "/about.html" "/assets/app.css" "/assets/app.js" "/api/products.json" "/api/users.json" "/api/products.json?page=2" "/products.html?q=widget" "/api/users.json?role=member" "/api/products.json?sort=price" )
echo "[traffic] streaming benign requests through $P → $T  (Ctrl-C to stop)"
i=0
while true; do
  i=$((i + 1))
  p=${paths[$((RANDOM % ${#paths[@]} + 1))]}
  if (( i % 9 == 0 )); then
    curl -s -x $P -X POST -H "Content-Type: application/json" --data '{"cart":[1,2],"qty":2}' "$T/api/checkout" -o /dev/null
  else
    curl -s -x $P "$T$p" -o /dev/null
  fi
  sleep 0.15
done
