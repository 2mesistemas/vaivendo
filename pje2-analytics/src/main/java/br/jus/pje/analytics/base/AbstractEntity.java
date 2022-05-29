package br.jus.pje.analytics.base;

import java.io.Serializable;

public abstract class AbstractEntity<E> implements Serializable {

    private static final long serialVersionUID = 1L;

    public abstract E getId();

    public abstract Boolean getAtivo();

    public abstract void setAtivo(Boolean ativo);

    @Override
    @SuppressWarnings("unchecked")
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AbstractEntity<E> other = (AbstractEntity<E>) obj;
        if (getId() == null) {
            if (other.getId() != null)
                return false;
        } else if (!getId().equals(other.getId()))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        if (getId() != null) {
            return getId().hashCode();
        } else {
            return super.hashCode();
        }
    }

    @Override
    public String toString() {
        return getClass().getName() + "[id = " + getId() + "]";
    }

}