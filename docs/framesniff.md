## IDEIAS E IMPLEMENTAÇÕES FUTURAS

Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

* Desenvolver uma TUI para sniffing (semelhante ao termshark).
* Desenvolver uma TUI para edição de frames de forma semelhante ao mitmproxy.
* Implementar um módulo para geração/edição de frames/pacotes.
* implementar editor de conteúdo de pacotes e frames assim como o mitmproxy, usar "select-editor" abrir o editor com o conteúdo do frame, quando o usuário salvar alterar o conteúdo e permitir ele realizar o replay.
* Permitir o usuário escolher se ele quer ou não incluir os metadados na captura, se ele escolher que não quer, não será possível realizar a visualização estilo wireshark do campos.
* Se inspirar no mitmproxy para permitir o usuário desenvolver seus próprio plugins/scripts para manipular a captura e comportamento da interface e trafégo.
* Captura em modo monitor realizada apenas via raw sockets; análise, descriptografia etc., tratadas a partir dos payloads LLC.
* Opção para os usuários enviarem frames devidamente criptografados para que os APs os aceitem.
* Permitir que os usuários forneçam um arquivo JSON com as informações necessárias para descriptografar frames protegidos, por exemplo:
  `{1: {"bssid": "", "ssid": "", "psk": "", "clients": {1: {"mac": "", "handshake": ""}}}}`
* Controle básico de interface sem `iw`, utilizando o módulo `wnlpy` em desenvolvimento.
* Tratar e explicar o possíve problema ao utilizar interfaces virtuais em modo monitor.
* Documentação para expressões de filtro; recomendar que os usuários capturem frames com `sniff` e analisem a saída JSON.
* Utilizar GitHub Docs.

---

## O QUE ESTÁ FALTANDO? PARA CORRIGIR / ADICIONAR
* Revisar os resultados dos parsers, comparar com o resultado do wireshark, e corrigir os parsers se necessário.
* Revisar os resultados dos parsers, e decidir quais campos de metadata são realmente necessários e suficientes para criar um TUI semelhante com a interaface do wireshark.
* Usar escrita atômica (tempfile + replace)
* Considerar JSON Lines para streaming
* Utilizar função que recebe um arquivo json com vários frames brutos em hexadecimal, e realiza o parse deles, escrevendo o resultado em um arquivo json. Isso para fazer um teste automatizado dos parsers, contra frames truncados, quebrados etc... 
* Adicionar uma seção de todos os artigos e manuais que explicam e definem os padrões dos frames, incluindo seus campos valores etc...
* Melhorar nomes de variáveis e strings
* Adicionar verificações adicionais de detecção de erros.
* Adicionar vídeos e imagens à documentação ou criar um vídeo tutorial.
* Verificar as bandas suportadas pela interface antes de realizar o channel hopping.
* Corrigir possíveis condições de corrida.
* Padronização e melhorias de legibilidade e usabilidade do framesniff
* Quando possível, criar tabelas de dispatch com name e description do handler. Para facilitar entendimento do usuário e apresentação na TUI.
* Atualizar todos os formats de struct, para utilizarem valores de constantes definidas, dessa forma irá eliminar boa parte dos hardcodes, irá melhorar a legibilidade, e significativamente a escalabilidade.
* Melhorar desempenho e ordem das operações.
* Melhorar filtro, permitir com que o usuário possa passar diretamente o nome de um tipo de frame, e assim obter o filtro que corresponde a ele.
* Analisar e decidir como irá funcionar o fluxo de utilzação de parsers enetre diferentes padrões, e definir uma estrutura padrão para cada padrão, começando por exemplo por dot1x.
* Analisar e decidir como llc irá importar os parsers. Analisar a estrutura de parse em dot1x e parsers em l3.
* Padronizar estrutura de todas as camadas e padrões.
* Revisar toda a arquitetura, avaliar e decidir.

## Melhorias:
* Aplicando boas práticas clean code, eficiência em memória e processamente, removendo boa parte de números mágicos, removendo vários IFs por mecanismo de dispatcher.
* Formato de paths de arquivos de log
* Estrutura de diretórios mais compativeis com o modelo OSI, e melhor escalabilidade.
* A maioria dos hardcodes foram removidos, queria remover todos mas dá muito trabalho, se por algum acaso 
* Desenvolvendo __main__.py para padronizar e automatizar testes.

## Explicações e esclarecimentos
* /core representa o motor de analise do modelo OSI, e o diretório layers representam as diferentes camadas do modelo.
* Todo esse projeto tenta replicar ao máximo o modelo OSI, para deixar o mais didático possível.
* Estou tentando ao máximo remover hardcodes, mas em protocolos de padrões de comunicação, muitas vezes não dá para fugir de formatos e números arbitrários.

## Padrões a serem seguidos
* Sempre montar dict ou fazer operações com valores, em memória, armazenando em variáveis antes de seres passada para o dict final, ou seja, não realizar lógica inline no dict. Isso se aplica principalmente para parsers internos usados como argumento de callback para a função unpack.
* Seguir padrão da função unpack, ou seja, sempre que precisa interpretar um valor desempacotado por struct.unpack ou srtuct.unpack_from passar o parser interno que irá receber os valores binários desempacotados, e irá interpretar eles.

# Decisões de arquitetura pendentes:
Minha arquitetura atualmente: ...

## Referências

[Hashcat](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)

### Parsers, padrões e protocolos:
https://learn.microsoft.com/en-us/windows-hardware/drivers/mobilebroadband/network-cost-information-element

## Desabafos durante todo o projeto kkkkkkk
* É muita coisa meu Deus, falta fazer parsing de muita coisa e olha lá, realmente estou chagando a conclusão que será muito difícil manter o projeto, são muitos parsers, muitos parsers próprietários também. Fato é que obviamente eu não sei o que significa cada campo ou seção do frame, mas estou disposto a saber, e isso é o mais importante.
* Um dos maiores desafios desse projeto, é o planejamento e padronização.

