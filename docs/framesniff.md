## IDEIAS E IMPLEMENTAÇÕES FUTURAS
Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

* Permitir com que a função sniff possa ser utilizada por outros parsers, a fim de permitir com que eles façam suas próprias analises, por isso que o resultado original retornado pela função de "parse" contém bytes não convertidos em hexadecimal.
* Permitir o usuário cerregar arquivo com padrões de filtro de frames.
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
* Adicionar suporte a parse de: FTP, SSH,

---

## O QUE ESTÁ FALTANDO? PARA CORRIGIR / ADICIONAR
* Testar filter_engine para acessar valores por chaves que são inteiros.
* Tornar iter_packts_from_json mais flexível, possivelmente criar uma função separada apenas ler json, utilizando o mecanismo de fallback de iter_packets_from_json.
* Adicionar descrição de parse com base nos valores do campo sempre que necessário, por exemplo: adicionar de descrição em parse EAPOL dando informações sobre o frame, indicando se é a mensagem 1, 2 3 ou 4. Ou definir a descrição dando informações sobre a rede, se WPA2 etc... Mas estou na dúvida, pensei aqui, talvez a melhor forma de fazer isso seja: Adicionar descrição de parse daquele campo específico no resultado de parsed que ele irá retornar, mas em seguida adicionar essa descrição em uma nova estrutura que vou criar, essa estrutura vai ser descrever o frame, o dispositivo de origem (se for ap, vai incluir informações sobre a rede), dispositivo destino, etc... e outras informações relevantes de acordo com padrão e DLT. Essa estrutura vai ser utilizada para montar a resumo de todo o trafégo de rede capturado/analisado.
* Fazer com a que a função " _build_eapol_line" detecte os frames eapol (1, 2, 3 e 4) a partir das informações do payload eapol, e se caso houver um frame de management ou data que contenha o bssid e outras informações que indicam que são da mesma origem dos frames eapol, então extrair o ssid automaticamente para gerar o arquivo de hashcat formato 22000, e se houver pmkid no frame eapol, então gerar também o arquivo hashcat formato 22001. Adicionar funcionalidade que irá detectar vários frames eapol e gerar vários arquivos hashcat 22000 ou 220001 (caso detecte pmkid), se nesse arquivo de captura a função não detectar algumas informações básicas como ssid ou sta_mac, então retornar a linha com os valores faltando, mas no lugar deles haverá um texto simples pendindo para inserir o que falta (seja ssid ou sta_mac por exemplo).
* Redefinir estrutura de retorno de parse de mac ou oui, para: {"addr": , "vendor": ,}, e atualizar todos os parsers e arquivos que chamam ".mac" ou ".oui": user_operations, common, scan_monitor, __main__.py, README.md.
* Criar componente de interface TUI padrão, semelhante ao wireshark. A estrutura pensanda está em docs/.
* Permitir o usuário encerrar automaticamente a captura após o arquivo de captura atingir um tamanho específico.
* Corrigir fluxo e apresentação de error de scan_monitor.
* Criar função em filter_engine que será utilizada por outros módulos para obter os valores de dicionário "parsed" diretamente, sem ter que digita-lo.
* Estou preucupado em fazer funcionar, depois vou revisar tudo.
* Revisar os resultados dos parsers, comparar com o resultado do wireshark, e corrigir os parsers se necessário.
* Corrigir possíveis condições de corrida.
* Melhorar nomes de variáveis e strings
* Padronização e melhorias de legibilidade e usabilidade do framesniff
* Atualizar todos os formats de struct, para utilizarem valores de constantes definidas, dessa forma irá eliminar boa parte dos hardcodes, irá melhorar a legibilidade, e significativamente a escalabilidade.
* Adicionar verificações adicionais de detecção de erros.
* Verificar as bandas suportadas pela interface antes de realizar o channel hopping.
* Adicionar uma seção de todos os artigos e manuais que explicam e definem os padrões dos frames, incluindo seus campos valores etc...
* Adicionar vídeos e imagens à documentação ou criar um vídeo tutorial.
* Quando possível, criar tabelas de dispatch com name e description do handler. Para facilitar entendimento do usuário e apresentação na TUI.
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
* Reducing unnecessary exceptions.

## Explicações e esclarecimentos
* /core representa o motor de analise do modelo OSI, e o diretório layers representam as diferentes camadas do modelo.
* Todo esse projeto tenta replicar ao máximo o modelo OSI, para deixar o mais didático possível.
* Estou tentando ao máximo remover hardcodes, mas em protocolos de padrões de comunicação, muitas vezes não dá para fugir de formatos e números arbitrários.

## Padrões a serem seguidos
* Utilizar a função "fail" apenas quando for realmente um erro que pode afetar todo restante do parse.
* Para nomes de chaves de valores em dicionários como "parsed", é recomendado que sigam o mesmo padrão de outros analisadores/sniffer de rede como scapy e wireshark, abreviados sempre que possível para facilitar o filtro do usuário, a documentação de filtro irá criada justamente para evitar consões.
* Em funções utilitárias que utilizam um parser diretamente, utilizar get_nested sempre que precisar obter valores em parsed.
* Sempre montar dict ou fazer operações com valores, em memória, armazenando em variáveis antes de seres passada para o dict final, ou seja, não realizar lógica inline no dict. Isso se aplica principalmente para parsers internos usados como argumento de callback para a função unpack.
* Seguir padrão da função unpack, ou seja, sempre que precisa interpretar um valor desempacotado por struct.unpack ou srtuct.unpack_from passar o parser interno que irá receber os valores binários desempacotados, e irá interpretar eles.
* Não realizar conversões ou transformações hexadecimais nos resultados de parsed, só _add_metadata faz isso. O encoder json em finish_capture já faz esse trabalho, e filter_engine detecta se o valor é bytes, se for, faz apenas uma conversão local para ser utilizada em operações de comparação. Com exceção de conversão bytes_for_mac ou bytes_for_oui.

# Decisões de arquitetura pendentes:
Minha arquitetura atualmente: ...

## Referências

[Hashcat](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)

### Parsers, padrões e protocolos:
https://learn.microsoft.com/en-us/windows-hardware/drivers/mobilebroadband/network-cost-information-element

## Desabafos durante todo o projeto kkkkkkk
* É muita coisa meu Deus, falta fazer parsing de muita coisa e olha lá, realmente estou chagando a conclusão que será muito difícil manter o projeto, são muitos parsers, muitos parsers próprietários também. Fato é que obviamente eu não sei o que significa cada campo ou seção do frame, mas estou disposto a saber, e isso é o mais importante.
* Um dos maiores desafios desse projeto, é o planejamento e padronização.

