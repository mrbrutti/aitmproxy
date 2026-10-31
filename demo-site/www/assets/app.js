fetch('/api/products.json').then(r => r.json()).then(d => {
  document.getElementById('list').textContent = d.products.length + ' products';
});
