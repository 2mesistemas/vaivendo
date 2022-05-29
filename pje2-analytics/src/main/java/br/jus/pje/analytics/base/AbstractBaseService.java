package br.jus.pje.analytics.base;

import java.util.NoSuchElementException;

import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public abstract class AbstractBaseService<E extends AbstractEntity<I>, I>
    implements BaseService<E, I> {

  @Override
  public E recuperarRecurso(I idRecurso) {

    return this.getRepository().findById(idRecurso).get();
  }

  @Override
  public Page<E> pesquisarRecurso(Example<E> exemploRecurso, Pageable pageable) {

    return this.getRepository().findAll(exemploRecurso, pageable);
  }

  @Override
  public E criarRecurso(E recurso) {

    recurso = this.getRepository().save(recurso);

    return recurso;
  }

  @Override
  public E alterarRecurso(E recurso) throws NoSuchElementException {

    if (recurso != null && recurso.getId() != null) {
      this.getRepository().findById(recurso.getId()).get();
      recurso = this.getRepository().save(recurso);
    }

    return recurso;
  }

  protected abstract JpaRepository<E, I> getRepository();
}