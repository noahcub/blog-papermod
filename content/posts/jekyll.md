---
title: Web estática con Jekyll
description: Web estática con Jekyll y Bundle
date: 2023-02-02 18:00:00 +0100
categories:
   - Unraid
tags:
   - Admin
weight: 1
---

## Configuración sistema para ejecutar web estática en local antes de subir a github

**Instalación de rubygems**

Instalamos el software necesario a través de DNF:
``` bash
sudo dnf install ruby rubygems ruby-devel gcc gcc-c++ rpm-build
```
Para Debian 12:
``` bash
sudo apt install ruby ruby-dev build-essential
```
Le decimos al administrador de gemas donde queremos que se instalen las gemas:
Editamos .zshrc y añadimos esto al final:

``` bash
# Install Ruby Gems to ~/gems
export GEM_HOME="$HOME/gems"
export PATH="$PATH:~/bin"
export PATH="$HOME/gems/bin:$PATH"
```
Recargamos el entorno de Zsh:
``` bash
source .zshrc
```
Ahora ya podemos instalar las gemas. Instalamos las gemas de jekyll y bundler:

``` bash
gem install jekyll bundler
```
Como estamos usando la plantilla de [just-the-docs](https://github.com/just-the-docs/just-the-docs-template) ya vienen preparada con un Gemfile que es el que indica las gemas necesarias para ejecutar en local con jekyll.

Ejecutamos dentro del directorio de nuestro proyecto:
``` bash
bundle install
```
Después:
``` bash
bundle exec jekyll serve
```
Se arrancará el servidor en:
``` bash
localhost:4000
```


Es posible que el sistema lance un error similar a este:
``` bash
zsh: jekyll: command not found...
Install package 'rubygem-jekyll' to provide command 'jekyll'? [N/y] nnn
```

Eso significa que no encuentra jekyll como comando. En mi sistema los ejecutables de las gemas se instalaban en el siguiente path:
~/bin  
Haciendo un ls aparecen los siguientes ejecutables:
``` bash
bundle   jekyll         kramdown  rake     safe_yaml
bundler  just-the-docs  listen    rougify
```
En [stacoverflow](https://stackoverflow.com/questions/53979362/you-dont-have-path-in-your-path-gem-executables-will-not-run-while-using) aportan una posible solución. Todo se limita a añdir al PATH el directorio donde se encuentran los ejecutables:

``` bash
nano .zshrc
copy and past these two lines of code at the end of the .zshrc

export GEM_HOME="$(ruby -e 'puts Gem.user_dir')"
export PATH="$PATH:$GEM_HOME/bin"
```
En ~/.local/share/gem/ruby se copia la carpeta ~/bin o bien se añade directamente esta última al path. 

Y si queremos eliminar todas las gemas instaladas de Ruby:
``` bash
 for i in 'gem list --no-versions'; do gem uninstall -aIx $i; done

```
Para eliminar sólo una: 
``` bash
 gem uninstall gemaaaaaa --version 1.1.9  
```
***
Fuentes:  
[https://docs.github.com/es/pages/setting-up-a-github-pages-site-with-jekyll/creating-a-github-pages-site-with-jekyll](https://docs.github.com/es/pages/setting-up-a-github-pages-site-with-jekyll/creating-a-github-pages-site-with-jekyll)  
[https://docs.github.com/es/pages/setting-up-a-github-pages-site-with-jekyll/testing-your-github-pages-site-locally-with-jekyll](https://docs.github.com/es/pages/setting-up-a-github-pages-site-with-jekyll/testing-your-github-pages-site-locally-with-jekyll)  
[https://github.com/just-the-docs/just-the-docs-template/blob/main/README.md](https://github.com/just-the-docs/just-the-docs-template/blob/main/README.md)  
[http://brionescl.blogspot.com/2014/02/eliminar-todas-las-gemas-de-ruby.html](http://brionescl.blogspot.com/2014/02/eliminar-todas-las-gemas-de-ruby.html)  



