package william.apiwill.Repository;

import org.springframework.data.repository.CrudRepository;
import william.apiwill.Model.UsuarioModel;

public interface UsuarioRepository extends CrudRepository<UsuarioModel, Integer> {
}
