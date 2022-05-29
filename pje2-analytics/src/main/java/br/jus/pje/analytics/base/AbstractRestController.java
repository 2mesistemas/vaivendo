package br.jus.pje.analytics.base;

import br.jus.cnj.pje.pjecommons.model.services.PjeResponse;
import br.jus.cnj.pje.pjecommons.model.services.PjeResponseStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

public abstract class AbstractRestController <E extends AbstractEntity<I>, I>{

    @Autowired
    private ObjectMapper jacksonObjectMapper;

    @GetMapping(path = "/{idRecurso}", produces = MediaType.APPLICATION_JSON_VALUE)
    public PjeResponse<E> recuperarRecurso(@PathVariable("idRecurso") I idRecurso) {

        E recurso = this.getService().recuperarRecurso(idRecurso);

        PjeResponse<E> res = new PjeResponse<>(PjeResponseStatus.OK, "200", null, recurso);

        return res;
    }

    @GetMapping(produces=MediaType.APPLICATION_JSON_VALUE)
    public PjeResponse<Page<E>> pesquisarRecurso(Pageable page, @RequestParam(required = false, name = "simpleFilter") String simpleFilter) {

        PjeResponse<Page<E>> res = null;

        try {
            E recurso = !StringUtils.isEmpty(simpleFilter)
                    ? this.jacksonObjectMapper.readValue(simpleFilter, this.getEntityClass())
                    : this.getInstance();

            Page<E> pagina = this.getService().pesquisarRecurso(this.getExemplo(recurso), page);
            res = new PjeResponse<>(PjeResponseStatus.OK, HttpStatus.OK.toString(), null, pagina);
        } catch (Exception e) {
            List<String> msgs = new ArrayList<>(0);
            msgs.add("O modelo de pesquisa informado não é válido");
            res = new PjeResponse<>(PjeResponseStatus.ERROR, HttpStatus.OK.toString(), msgs,null);
            e.printStackTrace();
        }

        return res;
    }

    @Transactional(rollbackFor = Exception.class)
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public PjeResponse<E> criarRecurso(@Valid @RequestBody E recurso) {

        recurso = this.getService().criarRecurso(recurso);

        PjeResponse<E> res = new PjeResponse<>(PjeResponseStatus.OK, "200", null, recurso);

        return res;

    }

    @Transactional(rollbackFor = Exception.class)
    @PutMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public PjeResponse<E> alterarRecurso(@Valid @RequestBody E recurso, @PathVariable("idRecurso") I idRecurso) {

        PjeResponse<E> res = null;

        E recursoAtual = this.getService().recuperarRecurso(idRecurso);
        
        if(recursoAtual != null && recurso.getId().equals(recursoAtual.getId())) {
            try {
                recurso = this.getService().alterarRecurso(recurso);
                res = new PjeResponse<>(PjeResponseStatus.OK, "200", null, recurso);
            } catch (NoSuchElementException e) {
                List<String> msgs = new ArrayList<>(0);
                msgs.add("O recurso não existe, portanto não pode ser atualizado.");
                res = new PjeResponse<>(PjeResponseStatus.ERROR, HttpStatus.OK.toString(), msgs,null);
            }

        }

        return res;
    }

    @Transactional(rollbackFor = Exception.class)
    @DeleteMapping(path="/{idRecurso}", produces=MediaType.APPLICATION_JSON_VALUE)
    public PjeResponse<E> inativarRecurso(@PathVariable("idRecurso") I idRecurso) {
        PjeResponse<E> res = null;

        if(idRecurso != null) {
            try {
                E recurso = this.getService().recuperarRecurso(idRecurso);
                recurso.setAtivo(false);
                recurso = this.getService().alterarRecurso(recurso);
                res = new PjeResponse<>(PjeResponseStatus.OK, "200", null, recurso);
            } catch (NoSuchElementException e) {
                List<String> msgs = new ArrayList<>(0);
                msgs.add("O recurso não existe, portanto não pode ser atualizado.");
                res = new PjeResponse<>(PjeResponseStatus.ERROR, HttpStatus.OK.toString(), msgs,null);
            }

        }

        return res;
    }

    protected abstract BaseService<E, I> getService();

    protected Example<E> getExemplo(E recurso) {
        ExampleMatcher matcher = this.getExampleMatcher();
        Example<E> exemplo = Example.of(recurso, matcher);

        return exemplo;
    }

    protected ExampleMatcher getExampleMatcher(){
        return ExampleMatcher.matching().withIgnoreNullValues().withStringMatcher(ExampleMatcher.StringMatcher.CONTAINING);
    }

    @SuppressWarnings("unchecked")
	private String getGenericName()
    {
        return ((Class<E>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0]).getTypeName();
    }

    @SuppressWarnings("unchecked")
	private E getInstance() throws Exception {
        return (E) Class.forName(this.getGenericName()).getConstructor().newInstance();
    }

    @SuppressWarnings("unchecked")
    private Class<E> getEntityClass(){
        Class<E> entityClass = null;

        Type type = getClass().getGenericSuperclass();
        if (type instanceof ParameterizedType){
            ParameterizedType paramType = (ParameterizedType) type;
            if (paramType.getActualTypeArguments().length == 2){
                if (paramType.getActualTypeArguments()[1] instanceof TypeVariable){
                    throw new IllegalArgumentException("Could not guess entity class by reflection");
                }
                else{
                    entityClass = (Class<E>) paramType.getActualTypeArguments()[0];
                }
            }
            else{
                entityClass = (Class<E>) paramType.getActualTypeArguments()[0];
            }
        }
        else{
            throw new IllegalArgumentException("Could not guess entity class by reflection");
        }

        return entityClass;
    }

}
