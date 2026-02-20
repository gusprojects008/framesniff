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
