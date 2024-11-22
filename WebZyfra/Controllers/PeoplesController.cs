using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Security.Cryptography;

namespace WebZyfra.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PeoplesController : ControllerBase
    {
        private static Dictionary<string, (string PasswordHash, int Status)> validUsers = new Dictionary<string, (string, int)>();
        private static Dictionary<string, string> sessions = new Dictionary<string, string>(); // sessionId -> username

        public PeoplesController()
        {
            LoadUsers();
            LoadSessions();
            EnsurePasswordsAreHashed(); // Убедимся, что все пароли в файле захэшированы
        }

        // Загрузка пользователей из файла
        private void LoadUsers()
        {
            if (System.IO.File.Exists("users.txt"))
            {
                var lines = System.IO.File.ReadAllLines("users.txt");
                validUsers.Clear();
                foreach (var line in lines)
                {
                    var parts = line.Split(',');
                    if (parts.Length == 3)
                    {
                        validUsers[parts[0]] = (parts[1], int.Parse(parts[2]));
                    }
                }
            }
        }

        // Сохранение пользователей в файл
        private void SaveUsers()
        {
            var lines = validUsers.Select(user => $"{user.Key},{user.Value.PasswordHash},{user.Value.Status}");
            System.IO.File.WriteAllLines("users.txt", lines);
        }

        // Загрузка сессий из файла
        private void LoadSessions()
        {
            if (System.IO.File.Exists("sessions.txt"))
            {
                var lines = System.IO.File.ReadAllLines("sessions.txt");
                sessions.Clear();
                foreach (var line in lines)
                {
                    var parts = line.Split(',');
                    if (parts.Length == 2)
                    {
                        sessions[parts[0]] = parts[1]; // sessionId -> username
                    }
                }
            }
        }

        // Сохранение сессий в файл
        private void SaveSessions()
        {
            var lines = sessions.Select(session => $"{session.Key},{session.Value}");
            System.IO.File.WriteAllLines("sessions.txt", lines);
        }

        // Убедимся, что все пароли захэшированы
        private void EnsurePasswordsAreHashed()
        {
            bool updated = false;

            foreach (var user in validUsers.ToList())
            {
                if (!IsHashed(user.Value.PasswordHash))
                {
                    validUsers[user.Key] = (PasswordHasher.HashPassword(user.Value.PasswordHash), user.Value.Status);
                    updated = true;
                }
            }

            if (updated)
            {
                SaveUsers(); // Сохраняем изменения
            }
        }

        // Проверка, является ли строка хэшем (условная проверка на длину Base64)
        private bool IsHashed(string password)
        {
            return password.Length == 44; // Длина Base64 строки для SHA256
        }

        // GET /api/peoples - Получить список всех пользователей
        [HttpGet]
        public IActionResult GetAllUsers()
        {
            return Ok(validUsers.Keys);
        }

        // POST /api/peoples/register - Регистрация нового пользователя
        [HttpPost("register")]
        public IActionResult Register([FromBody] LoginRequest request)
        {
            if (validUsers.ContainsKey(request.Username))
            {
                return BadRequest("Пользователь уже существует.");
            }

            // Хэшируем пароль и добавляем нового пользователя
            validUsers[request.Username] = (PasswordHasher.HashPassword(request.PasswordHash), 0);
            SaveUsers();
            return Ok("Пользователь зарегистрирован.");
        }

        // POST /api/peoples/login - Вход пользователя
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            if (!validUsers.ContainsKey(request.Username))
            {
                return NotFound("Пользователь не найден.");
            }

            var user = validUsers[request.Username];
            var hashedPassword = PasswordHasher.HashPassword(request.PasswordHash);

            // Сравнение пароля
            if (user.PasswordHash != hashedPassword)
            {
                return Unauthorized("Неверный пароль.");
            }

            // Проверка на активную сессию
            if (user.Status == 1)
            {
                return BadRequest("Пользователь уже вошел в систему.");
            }

            // Создание сессии
            string sessionId = Guid.NewGuid().ToString();
            sessions[sessionId] = request.Username;

            // Обновление статуса пользователя на 1 (активен)
            validUsers[request.Username] = (user.PasswordHash, 1);

            SaveSessions();
            SaveUsers();

            return Ok(new { SessionId = sessionId, request.Username });
        }

        // POST /api/peoples/logout - Выход пользователя по адресу сессии
        [HttpPost("logout")]
        public IActionResult Logout([FromBody] LogoutRequest request)
        {
            // Ищем сессию по SessionId
            if (!sessions.ContainsKey(request.SessionId))
            {
                return NotFound("Сессия не найдена.");
            }

            var username = sessions[request.SessionId];

            // Удаляем сессию
            sessions.Remove(request.SessionId);

            // Меняем статус пользователя на 0 (неактивен)
            validUsers[username] = (validUsers[username].PasswordHash, 0);

            SaveSessions();
            SaveUsers();

            return Ok($"Пользователь {username} вышел из системы.");
        }

        // Получение сессии пользователя по логину и паролю
        [HttpGet("session")]
        public IActionResult GetUserSession([FromQuery] string username, [FromQuery] string password)
        {
            // Проверка на наличие пользователя
            if (!validUsers.ContainsKey(username))
            {
                return NotFound("Пользователь не найден.");
            }

            var user = validUsers[username];
            var hashedPassword = PasswordHasher.HashPassword(password);

            // Проверка пароля
            if (user.PasswordHash != hashedPassword)
            {
                return Unauthorized("Неверный пароль.");
            }

            // Поиск сессии для пользователя
            var session = sessions.FirstOrDefault(s => s.Value == username);

            if (session.Equals(default(KeyValuePair<string, string>)))
            {
                return NotFound("Активной сессии нет.");
            }

            return Ok(new { SessionId = session.Key });
        }
    }

    public class LoginRequest
    {
        public string Username { get; set; }
        public string PasswordHash { get; set; }
    }

    public class LogoutRequest
    {
        public string SessionId { get; set; }
    }

    public static class PasswordHasher
    {
        public static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hashedBytes);
            }
        }
    }
}
