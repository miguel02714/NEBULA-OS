# 🌌 NebulaOS

![NebulaOS Banner](./assets/nebula-banner.png)

Um sistema operacional **web-based** que simula uma experiência de desktop completa no navegador.  
Possui **janelas, terminal, explorador de arquivos, personalização de wallpaper, temas, calculadora e até um navegador integrado**.  

---

## 📑 Índice
- [Recursos](#-recursos)
- [Terminal](#-terminal)
- [Personalização](#-personalização)
- [Navegador](#-navegador)
- [Nebula Intelligence](#-nebula-intelligence)
- [Calculadora](#-calculadora)
- [Menu de Contexto](#-menu-de-contexto)
- [Relógio Widget](#-relógio-widget)
- [Persistência](#-persistência)
- [Aplicativos Disponíveis](#-aplicativos-disponíveis)
- [Tecnologias Usadas](#-tecnologias-usadas)
- [Boot](#-boot)
- [Screenshots](#-screenshots)

---

## 🚀 Recursos
- Toast notifications.
- Cookies + LocalStorage para persistência de dados (até 10 anos).
- Status do usuário:
  - Conexão Wi-Fi.
  - Bateria (nível e carregamento).
  - Agente do navegador (User Agent).
  - Relógio atualizado em tempo real.
- Gerenciamento de janelas:
  - Abrir, fechar, minimizar, maximizar, restaurar.
  - Ícones na **taskbar** e **desktop**.
  - Drag & drop para mover.

---

## 💻 Terminal
Comandos disponíveis:
```bash
help             # Lista comandos
nebula clean     # Limpa a tela
echo <texto>     # Exibe texto
date             # Data/hora
whoami           # Usuário atual
neofetch         # Info do sistema
ls               # Lista arquivos/pastas
cd <dir|..|/>    # Navega entre pastas
open <arquivo>   # Abre no editor
cat <arquivo>    # Exibe conteúdo
bg set <...>     # Define wallpaper
bg reset         # Reseta wallpaper
