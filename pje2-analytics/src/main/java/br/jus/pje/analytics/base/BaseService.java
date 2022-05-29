package br.jus.pje.analytics.base;

import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface BaseService<E, I> {

    E recuperarRecurso(I idRecurso);
    Page<E> pesquisarRecurso(Example<E> exemploRecurso, Pageable pageable);
    E criarRecurso(E recurso);
    E alterarRecurso(E recurso);

}