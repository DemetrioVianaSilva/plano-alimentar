# Plano Alimentar

Site estático (GitHub Pages) + Supabase (login, planos por paciente, registros diários).

- `index.html`: app do paciente e painel da nutricionista.
- `supabase/schema.sql`: tabelas, permissões (RLS) e funções. Os logins iniciais foram criados à parte.

A chave no `index.html` é a chave pública "anon"; a proteção dos dados vem das regras de acesso (RLS) no banco.
