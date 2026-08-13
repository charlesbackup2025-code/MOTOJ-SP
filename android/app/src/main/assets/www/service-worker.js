const CACHE='motoja-sp-v1';
const ASSETS=['./','./index.html','./styles.css','./app.js','./manifest.webmanifest','./icon-192.png','./icon-512.png'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS))));
self.addEventListener('fetch',e=>e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request))));
self.addEventListener('push',e=>{let data={title:'MotoJá',body:'Você tem uma atualização.'};try{data=e.data?e.data.json():data}catch(_){}e.waitUntil(self.registration.showNotification(data.title,{body:data.body,icon:'icon-192.png',badge:'icon-192.png',data:{url:'./'}}));});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(list=>{for(const client of list){if('focus' in client)return client.focus();}return clients.openWindow(e.notification.data?.url||'./');}));});
