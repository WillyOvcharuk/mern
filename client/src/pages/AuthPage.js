import React, { useState, useEffect } from 'react'
import { useHttp } from '../hooks/http.hooks'
import { useMessage } from '../hooks/message.hook'


export const AuthPage = () => {
    const message = useMessage()
    const {loading, request, error} = useHttp()
    const [form, setForm] = useState({
      email:'',
      password:'',
    })

    useEffect(() => {
      message(error)
      //clearError()
    }, [error, message])


    const changeHandler = event => {
      setForm({...form, [event.target.name]: event.target.value})
    }

    const registerHandler = async () => {
      try {
        const data = await request('/api/auth/register', 'POST', {...form})
        message(data.message)
        console.log('Data: ', data)
      } catch(e){

      }
    }



    return (
      <div className="row">
        <div className="col s6 offset-s3"></div> 
        <h1>Get your links shorter</h1>
        <div className="card blue darken-1">
          <div className="card-content white-text">
            <span className="card-title">Authorization</span>
            <div>

              <div className="input-field">
                <input
                  placeholder="Введите email" 
                  id="email" 
                  type="text"
                  name="email"
                  className="yellow-input"
                  onChange={changeHandler}/>
                <label htmlFor="email">Email</label>
              </div>

              <div className="input-field">
                <input
                  placeholder="Введите пароль" 
                  id="password" 
                  type="password"
                  name="password"
                  className="yellow-input"
                  onChange={changeHandler}/>
                <label htmlFor="password">Password</label>
              </div>

            </div>
          </div>
          <div className="card-action">
            <button 
              className="btn yellow darken-4" 
              style={{marginRight: 10}}
              disabled={loading}
            >
              Войти
            </button>
            <button 
              className="btn grey lighten-1 black-text"
              onClick={registerHandler}
              disabled={loading}
            >
              Регистрация
            </button>
          </div>
        </div>
      </div>
      )
}