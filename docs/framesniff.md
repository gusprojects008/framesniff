## Ideias e implementações futuras

Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

* Utilizar GitHub Docs.
* Opção para os usuários enviarem frames devidamente criptografados para que os APs os aceitem.
* Controle básico de interface sem `iw`, utilizando o módulo `wnlpy` em desenvolvimento.

---

## O que está faltando? para corrigir / adicionar
* Substituir requirements.txt por pyproject e ajustar setup.sh.
* Fazer com a que a função " _build_eapol_line" detecte os frames eapol (1, 2, 3 e 4) a partir das informações do payload eapol, e se caso houver um frame de management ou data que contenha o bssid e outras informações que indicam que são da mesma origem dos frames eapol, então extrair o ssid automaticamente para gerar o arquivo de hashcat formato 22000, e se houver pmkid no frame eapol, então gerar também o arquivo hashcat formato 22001. Adicionar funcionalidade que irá detectar vários frames eapol e gerar vários arquivos hashcat 22000 ou 220001 (caso detecte pmkid), se nesse arquivo de captura a função não detectar algumas informações básicas como ssid ou sta_mac, então retornar a linha com os valores faltando, mas no lugar deles haverá um texto simples pendindo para inserir o que falta (seja ssid ou sta_mac por exemplo).
* Padronização e melhorias de legibilidade e usabilidade do framesniff
* Verificar as bandas suportadas pela interface antes de realizar o channel hopping.
* Adicionar vídeos e imagens à documentação ou criar um vídeo tutorial.
* Corrigir possíveis condições de corrida.

## Melhorias:
* Arquitetura melhorada, maior escalabilidade, está explicada em cli-core/templates/python.
* Aplicando boas práticas clean code,removendo vários IFs por mecanismo de dispatcher.
* Reestruturação de core/ para ser mais conceitualmente compativel com os conceitos de padrões de comunicação e modelo OSI.
* __main__.py criado para padronizar e automatizar testes.
* Começando a desenvolver a arquitetura da TUI do framesniff. Com a maioria das funcionalidades do wireshark, e até algumas adicionais.

## Explicações e esclarecimentos

## Padrões a serem seguidos

# Decisões de arquitetura pendentes:
Minha arquitetura atualmente: ...

## Referências
[Hashcat](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)

### Parsers, padrões e protocolos:
https://learn.microsoft.com/en-us/windows-hardware/drivers/mobilebroadband/network-cost-information-element

## Desabafos durante todo o projeto kkkkkkk
* É muita coisa meu Deus, falta fazer parsing de muita coisa e olha lá, realmente estou chagando a conclusão que será muito difícil manter o projeto, são muitos parsers, muitos parsers próprietários também. Fato é que obviamente eu não sei o que significa cada campo ou seção do frame, mas estou disposto a saber, e isso é o mais importante.
* Um dos maiores desafios desse projeto, é o planejamento e padronização.
