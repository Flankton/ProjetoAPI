package william.apiwill.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import william.apiwill.Model.UsuarioModel;
import william.apiwill.Repository.UsuarioRepository;

import java.util.List;

@RestController
public class UsuarioController {

    @Autowired
    private UsuarioRepository repository;

    @GetMapping(path="/api/usuario/{id}")
    public ResponseEntity consultar(@PathVariable("id") Integer id){
        return repository.findById(id)
                .map(record -> ResponseEntity.ok().body(record))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping(path="/api/usuario/salvar")
    public UsuarioModel salvar(@RequestBody UsuarioModel usuario){

        return repository.save(usuario);
    }

    @PutMapping(path="/api/usuario/{id}")
    public ResponseEntity update(@PathVariable("id") Integer id,
                                 @RequestBody UsuarioModel usuario) {
        return repository.findById(id)
                .map(record -> {
                    record.setName(usuario.getName());
                    record.setLogin(usuario.getLogin());
                    record.setPass(usuario.getPass());
                    UsuarioModel updated = repository.save(record);
                    return ResponseEntity.ok().body(updated);
                }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping(path="/api/usuario")
    public List findAll(){
        return (List) repository.findAll();
    }

    @DeleteMapping(path ={"/api/usuario/{id}"})
    public ResponseEntity <?> delete(@PathVariable Integer id) {
        return repository.findById(id)
                .map(record -> {
                    repository.deleteById(id);
                    return ResponseEntity.ok().build();
                }).orElse(ResponseEntity.notFound().build());
    }
}
