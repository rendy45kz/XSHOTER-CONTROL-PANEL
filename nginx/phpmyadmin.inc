location = /phpmyadmin { return 301 /phpmyadmin/; }
location /phpmyadmin/ {
    alias /usr/share/phpmyadmin/;
    index index.php;
    location ~ /(libraries|setup|templates|locale) { deny all; return 404; }
    location ~ /(.+\.(json|lock|md)) { deny all; return 404; }
    location ~ ^/phpmyadmin/(.*\.php)$ {
        alias /usr/share/phpmyadmin/$1;
        include /etc/nginx/fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $request_filename;
        fastcgi_param HTTPS on;
        fastcgi_pass unix:/run/php/xshoter-pma.sock;
    }
}
