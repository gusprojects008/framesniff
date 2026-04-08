## IDEIAS E IMPLEMENTAÇÕES FUTURAS

Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

* implementar editor de conteúdo de pacotes e frames assim como o mitmproxy, usar "select-editor" abrir o editor com o conteúdo do frame, quando o usuário salvar alterar o conteúdo e permitir ele realizar o replay.
* Captura em modo monitor realizada apenas via raw sockets; análise, descriptografia etc., tratadas a partir dos payloads LLC.
* Opção para os usuários enviarem frames devidamente criptografados para que os APs os aceitem.
* Permitir que os usuários forneçam um arquivo JSON com as informações necessárias para descriptografar frames protegidos, por exemplo:
  `{1: {"bssid": "", "ssid": "", "psk": "", "clients": {1: {"mac": "", "handshake": ""}}}}`
* Funcionalidade de channel hopping em um intervalo de canais definido pelo usuário; o usuário pode excluir canais ou especificar bandas.
* `createpkt`: editor gráfico de pacotes para raw hex; salvar pacotes editados individualmente ou todos.
* `pcaptohex`: extrair frames em raw hex de um pcap para uma estrutura `.json`.
* Controle básico de interface sem `iw`, utilizando o módulo `wnlpy` em desenvolvimento.
* Possivelmente separar o channel hopping em um comando independente.
* Permitir que os usuários definam a largura do canal no channel hopping.
* Tratar o comportamento de interfaces virtuais em modo monitor.
* Documentação para expressões de filtro; recomendar que os usuários capturem frames com `sniff` e analisem a saída JSON.
* Fornecer padrões de uso com exemplos: por exemplo, converter capturas do framesniff para pcap com `hextopcap`, ou reproduzir frames capturados usando `send-raw`.
* Utilizar GitHub Docs.

---

## O QUE ESTÁ FALTANDO? PARA CORRIGIR / ADICIONAR
* Adaptar todas funções de parse para o novo retorno consistente de "unpack". E decidir como e onde o LLC vai ser parseado.
* Estrutura e fluxo de funções para parsing de IEs, exemplo: parse_ssid(value, raw, offset) -> função interna passada como callback para unpack (ela recebe value e `**kwargs`) -> retorna "parsed" com tudo necessário. 
* Acho que encontrei uma forma de resolver o problema da geração de arvore de parse com os dados necessários para desenvolver uma interface gŕafica que permita edição/navegação/inspeção de frames e pacotes. Cada função de principal de parse de frame de uma DLT de um padrão específico, irá criar o seu próprio contexto de parse, dessa forma, possívelmente, a própria função unpack irá lidar com a criação de metadados necessários com as informações do campo (offsetr inicio/final, length, parent, children etc...).
* Possívelmente irei ter que criar um módulo chamado dissector ou dispatch, para fornecer uma interface única para módulos como "user_operations" obterem o parse de frames de uma DLT de um padrão específico.
* trocar nome dispacther para apenas dispatch
* e se houvesse um dispatcher geral para todo o projeto? de acordo como o padrão específico? iria expor uma classe, e o módulo central do padrão iria instanciar apenas o dispatcher do seu padrão.
Tudo isso para padronizar chaves e valores específicos, por exemplo, raw, start_offset, end_offset, e outros que futuramente vou precisar adicionar, para poder implementar interfaces como a do wireshark, e permitir o usuário visualizar e navegar por cada byte ou conjunto de bytes correspondente a um campo do pacote. Ou também, fornecer itnerface para o usuário editar o frame como um json, e gerar o frame bruto personalizado pronto para ser salvo em um arquivo json, ou enviado diretamente através de uma interface específica.
* Criar função que recebe um type, utiliza tabela de dispatch e retorna diretamente o conteúdo parseado
* Adicionar função de channel hopper como função independente no argparser
* Revisar módulo radiotap_header.py.
* Pensar na possibilidade de criar um módulo apenas para parse de frames (parse.py), e um módulo apenas de classes para cada tipo de frame, e expõe apenas as tabelas de dispatch de parsers para eles. Ou criar um módulo para cada tipo de frame, e assim, expor uma tabela de dispatch em cada um.
* Adicionar suporte hashcat 22000 padrão (bitmask 0), recebendo frame eapol 1 e 2.
* Corrigir função 
* Testar todas as funcionalidades.
* Melhorar nomes de funções no framesniff.py
* Transferir funções para os módulos corretos, como: generate_22000 -> user_operations, mudar nome de generate_22000 para generate_hashcar_22000
* Corrigir tui da funcionalidade scan-monitor
* Corrigir funcionalidade generate 2200
* Utilizar função que recebe um arquivo json com vários frames brutos em hexadecimal, e realiza o parse deles, escrevendo o resultado em um arquivo json. Isso para fazer um teste automatizado dos parsers, contra frames truncados, quebrados etc... 
* revisar os chaves que defini para campos importantes, como rt_hdr, mac_hdr etc...
* adicionar parser de: HT Operations, Overlapping BSS Scan Parameters
* corrgir parse de bitmap ht capabilities, tim, country code. 
* Corrigir setup.sh e README para instruir o usuário a utiliza diretamente o python dentro do .venv criado por setup.sh.
* Adicionar uma seção de todos os artigos e manuais que explicam e definem os padrões dos frames, incluindo seus campos valores etc...
* É muita coisa meu Deus, falta fazer parsing de muita coisa e olha lá, realmente estou chagando a conclusão que será muito difícil manter o projeto, são muitos parsers, muitos parsers próprietários também. Fato é que obviamente eu não sei o que significa cada campo ou seção do frame, mas estou disposto a saber, e isso é o mais importante.
* Falta revisão e melhoramente de parsing de vendors specific, rsn capabilities, ht capabilities.
* Fazer com que todos ou se não a maioria dos campos de valores, sejam acompanhados com o número identificador e o tamanho.
* Parsear frame null function (no data)
* remover todas chamadas .hex() para uma string dentro de um dicionário
* Adicionar parser para vendors specifics: MICROSOFT WPA, Mediatek, MICROSOFT WMM/WME 
* Melhorar filtro, permitir com que o usuário possa passar diretamente o nome de um tipo de frame, e assim obter o filtro que corresponde a ele.
* Melhorar desempenho e ordem das operações.
* parseador de frames, o usuário poderá gerar um arquivo json com todos os frames parseados, com base em um arquivo json com vários frame brutos.
* Remover totalmente hardcodes.
* Melhorar nomes de variáveis e strings
* Corrigir prioridade e obrigatoriedade de argumentos do argparse
* Separar logs, colorir logs no terminal, logs normais no arquivo de logs.
* Melhorar path names, seprando com hifem o datetime.
* Encerrar o programa com logs no terminal, caso haja um error fatal.
* Adicionar instrução explicita explicando que o usuário deve executar o programa usando o python do venv.
* Criar módulo de constantes, para evitar número mágicos hardcoded.
* Completar a análise dos parâmetros tagged, country code, ERP/TIM, RM e capacidades estendidas.
* Refatorar todos os parsers para incluir **todos** os dados analisados, incluindo valores, tags, comprimentos etc.
* Revisar os parsers e suas saídas.
* Implementar um módulo para geração/edição de frames/pacotes.
* Adicionar verificações adicionais de detecção de erros.
* Tornar as mensagens de erro mais rastreáveis e claras.
* Desenvolver uma TUI para sniffing (semelhante ao tshark).
* Desenvolver uma TUI para createpkt.
* Manter verificações de segurança e de tipos apenas nas partes críticas do programa (validação de entrada e uso final).
* Adicionar vídeos e imagens à documentação ou criar um vídeo tutorial.
* Verificar as bandas suportadas pela interface antes de realizar o channel hopping.
* Melhorar a legibilidade do código e revisá-lo de acordo com os princípios SOLID.
* Corrigir possíveis condições de corrida.

## Melhorias:
* Aplicando boas práticas clean code, eficiência em memória e processamente, removendo boa parte de números mágicos, removendo vários IFs por mecanismo de dispatcher.
* Formato de paths de arquivos de log
* Estrutura de diretórios mais compativeis com o modelo OSI, e melhor escalabilidade.
* A maioria dos hardcodes foram removidos, queria remover todos mas dá muito trabalho, se por algum acaso 

## Explicações e esclarecimentos
* Todo esse projeto tenta replicar ao máximo o modelo OSI, para deixar o mais didático possível.
* A maioria dos hardcodes foram removidos, queria remover todos mas dá muito trabalho, se por algum acaso o IEEE decidir mudar o tamanho de algum campo, então se eu poder eu venho aqui e corrijo removendo o hardcode. Em protocolos de padrões, muitas vezes não dá para fugir de formatos e números arbitrários.
* Para mensagens de debug, usar "error" para erros relacionados a funções.
* Um dos maiores desafios desse projeto, é o planejamento e padronização.
* Aplicação mais amigável e colorida.

## Padrões a serem seguidos
* Realizar conversões hexadecimais dentro de variáveis
* Chaves internas da própria aplicação: parse_tree
* Utilizar unpack de forma padronizada, para desempacotar apenas um conjunto relacionado de bytes por vez, isso por causa do resultado parse_tree e como ele será utilizado pela interface gráfica para exibição e navegação hexadecimal pelo frame.

## Referências
[Hashcat](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)
### Parsers, padrões e protocolos:
https://learn.microsoft.com/en-us/windows-hardware/drivers/mobilebroadband/network-cost-information-element

# Decisões de arquitetura pendentes:
frame_dispatch ou body_dispatch ?
