## IDEIAS E IMPLEMENTAÇÕES FUTURAS

Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

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
* realizar padronização de nomes de todos os campos do resultado do parsers. Criar seção ou arquivo de guia para instruir o usuário a fazer o filtro de frames.
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
