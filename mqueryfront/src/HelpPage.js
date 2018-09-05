import React, {Component} from 'react';


class HelpPage extends Component {
    render() {
        return (
            <div className="container" style={{width: "80%"}}>
                <h1 className="text-center" style={{marginBottom: "40px"}}>help me?</h1>
                <h2>Ogólnie</h2>
                <p>
                    System mquery służy do wydajnego wyszukiwania próbek malware wśród naszych zbiorów.
                    Informacją wejściową jest reguła YARA, którą spełniają pożądane próbki. W wyniku działania systemu
                    użytkownik
                    otrzymuje listę pasujących próbek.
                </p>

                <div className="alert alert-warning">
                    Przy korzystaniu z systemu, przydatna będzie umiejętność pisania reguł
                    <a href="http://yara.readthedocs.io/en/v3.4.0/writingrules.html">YARA</a>.
                </div>

                <p>
                    Proces przetwarzania reguły YARA na wyniki składa się z kilku etapów. Najpierw następuje parsowanie
                    wprowadzonych reguł YARA, a później generowane są odpowiednie zapytania do UrsaDB. Baza danych
                    wykorzystywana
                    jest do wstępnego przesiewania próbek - jest to proces szybki, ale generujący false-positive.
                    Ostatecznie, wyniki zwrócone przez bazę danych są weryfikowane narzędziem YARA.
                </p>

                <p>
                    Przesiewanie pomaga ograniczyć zbiór próbek przeznaczonych do sprawdzenia narzędziem YARA o kilka
                    rzędów
                    wielkości. Ten dodatkowy krok jest konieczny ze względu na to, że naiwne przeszukiwanie całego
                    zbioru
                    próbek, tzn. uruchomienie YARA na wszystkich plikach, ze względu na ich liczbę mogłoby zajęć nawet
                    kilka tygodni.
                </p>

                <h2>Korzystanie z systemu</h2>
                <p>
                    Regułę YARA można napisać wpisać ręcznie w polu tekstowym na stronie głównej serwisu. Po uczynieniu
                    tego,
                    należy nacisnąć zielony przycisk "Query", aby rozpocząć wyszukiwanie. Do debugowania systemu służy
                    przycisk
                    "Parse", który zaprezentuje zapytania UrsaDB wygenerowane na podstawie wprowadzonej reguły YARA.
                </p>

                <p>
                    Po zleceniu wyszukiwania po prawej stronie powinna pojawić sie tabelka wraz z listą dopasowań oraz
                    pasek postępu. Wyniki wyszukiwania można pobierać pojedynczo przez interfejs webowy, albo pobrać
                    listę
                    wszystkich dopasowań w celu późniejszego obrobienia jej za pomocą zewnętrznych narzedzi (curl, wget
                    etc).
                </p>

                <div className="alert alert-danger">
                    <strong>Uwaga!</strong> W zależności od sposobu działania wewnętrznego optymalizatora oraz jakości
                    wprowadzonych reguł YARA, niektóre wyszukiwania mogą wykonywać się bardzo długo. Jeżeli czas
                    wyszukiwania jest nieakceptowalny (np. liczba dopasowań przekracza kilkaset tysięcy), należy
                    anulować
                    zadanie i spróbować ponownie z inną regułą.
                </div>

                <p>
                    Wprowadzoną regułę wraz z wynikami wyszukiwania można zapisać korzystając z przycisku "Save as".
                    Dzięki temu, będzie ona widoczna dla innych użytkowników pod przyjazną nazwą z poziomu menu "Load".
                </p>

                <h2>Kontakt</h2>
                <p>
                    Pomysłodawcą projektu oraz autorem pierwszego PoCa jest <a href="https://tailcall.net/">msm</a>.
                    Obecnie, po stronie CERTu rozwojem i utrzymaniem systemu zajmuje się <a
                    href="mailto:monk@cert.pl">monk</a>.
                </p>
            </div>
        );
    }
}

export default HelpPage;
